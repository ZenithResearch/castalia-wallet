//! AD-CUSTODY-01..04, using synthetic roots in a private filesystem namespace.
//! The admission check and empty-slot store below are test harness code only.
#![cfg(unix)]

use castalia_wallet_core::{
    CardanoFundingAccountV1, CardanoFundingNetworkV1, import_wallet,
    recovery_session::RecoverySession,
};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const LOCAL: &str = "disposable local test password";
const BACKUP: &str = "disposable encrypted backup password";
const RECOVERED: &str = "distinct temporary restore password";

fn random_name() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("castalia-test-{}", random_name()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn slot(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    // All candidate slots are fresh and start at revision zero. link() places
    // complete bytes atomically only if the destination is still absent.
    fn insert(&self, destination: &Path, snapshot: &str) -> Result<()> {
        let temp = self.slot(&random_name());
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| "create_failed")?;
        file.write_all(snapshot.as_bytes())
            .map_err(|_| "write_failed")?;
        file.sync_all().map_err(|_| "sync_failed")?;
        let result = fs::hard_link(&temp, destination).map_err(|err| match err.kind() {
            ErrorKind::AlreadyExists => "slot_occupied",
            _ => "install_failed",
        });
        fs::remove_file(temp).map_err(|_| "cleanup_failed")?;
        result
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(session: &mut RecoverySession, command: Value) -> Result<Value> {
    session.invoke(&Zeroizing::new(command.to_string()))
}
fn field<'a>(object: &'a Value, name: &str) -> Result<&'a str> {
    object[name].as_str().ok_or("missing_field")
}
fn status(session: &mut RecoverySession) -> Value {
    invoke(session, json!({"operation":"state"})).unwrap()
}
// Never include a successful result (possibly an encrypted snapshot) in
// failure diagnostics when checking that an operation was refused.
fn refused<T>(result: Result<T>, expected: &'static str) {
    match result {
        Err(reason) => assert_eq!(reason, expected),
        Ok(_) => panic!("operation unexpectedly succeeded"),
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Descriptor {
    root: String,
    account: CardanoFundingAccountV1,
}
impl Descriptor {
    fn derive(snapshot: &str, password: &str, network: &CardanoFundingNetworkV1) -> Result<Self> {
        let value: Value = serde_json::from_str(snapshot).map_err(|_| "snapshot_json")?;
        if value["schema"] != "castalia.wallet-local.v1" || value["revision"] != 1 {
            return Err("snapshot_version");
        }
        let wallet = import_wallet(field(&value, "custody")?.as_bytes(), password)
            .map_err(|_| "candidate_custody")?;
        let account = wallet
            .cardano_funding_account(network)
            .map_err(|_| "account")?;
        Ok(Self {
            root: wallet.public_key_hex(),
            account,
        })
    }
}

#[derive(Clone)]
struct Candidate {
    token: String,
    snapshot: Zeroizing<String>,
    root: String,
}
impl Candidate {
    fn from_preview(session: &mut RecoverySession, preview: &Value) -> Result<Self> {
        let token = field(preview, "token")?.to_owned();
        let staged = invoke(
            session,
            json!({"operation":"commit_candidate","token":token,"expected_revision":0}),
        )?;
        if staged["expected_revision"] != 0 {
            return Err("staged_revision");
        }
        Ok(Self {
            token,
            snapshot: Zeroizing::new(field(&staged, "snapshot")?.to_owned()),
            root: field(preview, "public_key")?.to_owned(),
        })
    }
    // Same bytes and pending token are required even when the caller lost the
    // result after insert. A different winner can never be overwritten here.
    fn reconcile(&self, session: &mut RecoverySession, slot: &Path) -> Result<()> {
        let persisted = fs::read(slot).map_err(|_| "slot_read")?;
        if persisted != self.snapshot.as_bytes() {
            return Err("different_winner");
        }
        invoke(
            session,
            json!({"operation":"confirm_commit","token":self.token,"snapshot":self.snapshot.as_str()}),
        )?;
        Ok(())
    }
}

struct Installed {
    session: RecoverySession,
    descriptor: Descriptor,
    snapshot: Zeroizing<String>,
}
fn create(store: &Scratch, slot: &Path, network: &CardanoFundingNetworkV1) -> Installed {
    let mut session = RecoverySession::new();
    let preview = invoke(
        &mut session,
        json!({"operation":"prepare_create","created_at":1,"password":LOCAL,"expected_revision":0}),
    )
    .unwrap();
    let candidate = Candidate::from_preview(&mut session, &preview).unwrap();
    let descriptor = Descriptor::derive(&candidate.snapshot, LOCAL, network).unwrap();
    assert_eq!(descriptor.root, candidate.root);
    store.insert(slot, &candidate.snapshot).unwrap();
    candidate.reconcile(&mut session, slot).unwrap();
    Installed {
        session,
        descriptor,
        snapshot: candidate.snapshot,
    }
}
impl Installed {
    fn backup(&mut self) -> Zeroizing<String> {
        let v = invoke(
            &mut self.session,
            json!({"operation":"export_recovery","password":BACKUP}),
        )
        .unwrap();
        Zeroizing::new(field(&v, "file").unwrap().to_owned())
    }
}

struct Admission<'a> {
    controller_slot: &'a Path,
    controller: &'a Descriptor,
    secondary: &'a Descriptor,
    network: &'a CardanoFundingNetworkV1,
}
impl Admission<'_> {
    fn stage(
        &self,
        session: &mut RecoverySession,
        slot: &Path,
        backup: &str,
        pass: &str,
        revision: u64,
    ) -> Result<Candidate> {
        // Paths are fixture-owned named children of one fresh private directory.
        if slot == self.controller_slot {
            return Err("protected_controller_store");
        }
        if slot.try_exists().map_err(|_| "slot_read")? {
            return Err("slot_occupied");
        }
        let preview = invoke(
            session,
            json!({"operation":"prepare_restore","file":backup,"file_password":pass,"password":RECOVERED,"expected_revision":revision}),
        )?;
        let result = (|| {
            let candidate = Candidate::from_preview(session, &preview)?;
            let imported = Descriptor::derive(&candidate.snapshot, RECOVERED, self.network)?;
            if imported.root != candidate.root {
                return Err("candidate_root");
            }
            if imported.root == self.controller.root
                || imported.account.payment_key_hash() == self.controller.account.payment_key_hash()
            {
                return Err("same_controller");
            }
            if imported != *self.secondary {
                return Err("secondary_descriptor");
            }
            Ok(candidate)
        })();
        if result.is_err() {
            invoke(session, json!({"operation":"cancel"}))?;
        }
        result
    }
}
fn assert_empty(session: &mut RecoverySession) {
    let state = status(session);
    assert_eq!(state["configured"], false);
    assert_eq!(state["unlocked"], false);
    assert_eq!(state["revision"], 0);
}
fn unlock_verified(
    slot: &Path,
    password: &str,
    expected: &Descriptor,
    network: &CardanoFundingNetworkV1,
) {
    let persisted = Zeroizing::new(fs::read_to_string(slot).unwrap());
    let mut session = RecoverySession::new();
    invoke(
        &mut session,
        json!({"operation":"observe","snapshot":persisted.as_str()}),
    )
    .unwrap();
    let state = invoke(
        &mut session,
        json!({"operation":"unlock","snapshot":persisted.as_str(),"password":password}),
    )
    .unwrap();
    assert_eq!(state["revision"], 1);
    assert_eq!(state["public_key"], expected.root);
    assert_eq!(state["membership_active"], false);
    assert!(Descriptor::derive(&persisted, password, network).unwrap() == *expected);
}

// The stock recovery dispatcher also contains ML-DSA operations. Its debug
// stack frames need more than the default macOS libtest worker stack.
fn on_recovery_stack(run: fn()) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn independent_roots_restore_only_the_expected_secondary_into_an_empty_slot() {
    on_recovery_stack(check_descriptor_and_backup);
}

fn check_descriptor_and_backup() {
    let store = Scratch::new();
    let network = CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap();
    let controller_slot = store.slot("controller");
    let destination = store.slot("recovered");
    let mut c = create(&store, &controller_slot, &network);
    let mut r = create(&store, &store.slot("secondary"), &network);
    let mut w = create(&store, &store.slot("other"), &network);
    assert_ne!(c.descriptor.root, r.descriptor.root);
    assert_ne!(
        c.descriptor.account.payment_key_hash(),
        r.descriptor.account.payment_key_hash()
    );
    let installed = r.descriptor.clone();
    let admission = Admission {
        controller_slot: &controller_slot,
        controller: &c.descriptor,
        secondary: &installed,
        network: &network,
    };
    let r_backup = r.backup();
    let mut target = RecoverySession::new();
    refused(
        admission.stage(&mut target, &controller_slot, &r_backup, BACKUP, 0),
        "protected_controller_store",
    );
    refused(
        admission.stage(
            &mut target,
            &destination,
            &r_backup,
            "incorrect backup password",
            0,
        ),
        "recovery_file_invalid",
    );
    let mut tampered: Value = serde_json::from_str(&r_backup).unwrap();
    let mut ciphertext = field(&tampered, "ciphertext").unwrap().as_bytes().to_vec();
    ciphertext[0] = if ciphertext[0] == b'A' { b'B' } else { b'A' };
    tampered["ciphertext"] = Value::String(String::from_utf8(ciphertext).unwrap());
    refused(
        admission.stage(&mut target, &destination, &tampered.to_string(), BACKUP, 0),
        "recovery_file_invalid",
    );
    let data = invoke(
        &mut r.session,
        json!({"operation":"export_data","password":BACKUP,"exported_at":2}),
    )
    .unwrap();
    refused(
        admission.stage(
            &mut target,
            &destination,
            field(&data, "file").unwrap(),
            BACKUP,
            0,
        ),
        "data_file_requires_recovery",
    );
    refused(
        admission.stage(&mut target, &destination, &w.backup(), BACKUP, 0),
        "secondary_descriptor",
    );

    let first_c = invoke(
        &mut c.session,
        json!({"operation":"export_recovery","password":BACKUP}),
    )
    .unwrap();
    let second_c = invoke(
        &mut c.session,
        json!({"operation":"export_recovery","password":BACKUP}),
    )
    .unwrap();
    let first = field(&first_c, "file").unwrap();
    let second = field(&second_c, "file").unwrap();
    assert!(first != second);
    // Ordinary restoration of C is valid. The independence guard specifically
    // rejects using that same root as C's secondary credential.
    let mut own = RecoverySession::new();
    let own_preview = invoke(&mut own,json!({"operation":"prepare_restore","file":second,"file_password":BACKUP,"password":RECOVERED,"expected_revision":0})).unwrap();
    let own_candidate = Candidate::from_preview(&mut own, &own_preview).unwrap();
    let own_slot = store.slot("controller-copy");
    store.insert(&own_slot, &own_candidate.snapshot).unwrap();
    own_candidate.reconcile(&mut own, &own_slot).unwrap();
    unlock_verified(&own_slot, RECOVERED, &c.descriptor, &network);
    for backup in [first, second] {
        refused(
            admission.stage(&mut target, &destination, backup, BACKUP, 0),
            "same_controller",
        );
    }
    for wrong in [
        CardanoFundingNetworkV1::testnet(42, &"12".repeat(32)).unwrap(),
        CardanoFundingNetworkV1::testnet(2, &"13".repeat(32)).unwrap(),
    ] {
        let wrong_descriptor = Descriptor::derive(&r.snapshot, LOCAL, &wrong).unwrap();
        assert_eq!(
            wrong_descriptor.account.address(),
            installed.account.address()
        );
        assert_eq!(
            wrong_descriptor.account.payment_key_hash(),
            installed.account.payment_key_hash()
        );
        let altered = Admission {
            network: &wrong,
            ..admission
        };
        refused(
            altered.stage(&mut target, &destination, &r_backup, BACKUP, 0),
            "secondary_descriptor",
        );
    }
    assert_empty(&mut target);
    refused(
        invoke(
            &mut target,
            json!({"operation":"commit_candidate","token":"discarded","expected_revision":0}),
        ),
        "preview_expired",
    );
    assert!(!destination.exists());

    let accepted = admission
        .stage(&mut target, &destination, &r_backup, BACKUP, 0)
        .unwrap();
    assert_empty(&mut target);
    store.insert(&destination, &accepted.snapshot).unwrap();
    accepted.reconcile(&mut target, &destination).unwrap();
    assert_eq!(status(&mut target)["backup_verified"], true);
    unlock_verified(&destination, RECOVERED, &installed, &network);
    assert!(fs::read(&controller_slot).unwrap() == c.snapshot.as_bytes());
    unlock_verified(&controller_slot, LOCAL, &c.descriptor, &network);
    // Only public synthetic descriptors are reported for this run.
    println!(
        "public_descriptor_observation={}",
        json!({
            "controller":c.descriptor.account,"installedSecondary":installed.account,
            "recoveredSecondary":Descriptor::derive(&accepted.snapshot,RECOVERED,&network).unwrap().account,
        })
    );
}

#[test]
fn competing_previews_and_lost_confirmation_do_not_overwrite_either_store() {
    on_recovery_stack(check_store_conflict);
}

fn check_store_conflict() {
    let store = Scratch::new();
    let network = CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap();
    let cs = store.slot("controller");
    let dest = store.slot("recovered");
    let c = create(&store, &cs, &network);
    let mut r = create(&store, &store.slot("secondary"), &network);
    let backup = r.backup();
    let admission = Admission {
        controller_slot: &cs,
        controller: &c.descriptor,
        secondary: &r.descriptor,
        network: &network,
    };

    let mut first = RecoverySession::new();
    refused(
        admission.stage(&mut first, &dest, &backup, BACKUP, 1),
        "preview_stale",
    );
    let interrupted = admission
        .stage(&mut first, &dest, &backup, BACKUP, 0)
        .unwrap();
    refused(
        invoke(
            &mut first,
            json!({"operation":"commit_candidate","token":"wrong-token","expected_revision":0}),
        ),
        "preview_stale",
    );
    refused(
        invoke(
            &mut first,
            json!({"operation":"commit_candidate","token":interrupted.token,"expected_revision":1}),
        ),
        "preview_stale",
    );
    invoke(&mut first, json!({"operation":"cancel"})).unwrap();
    refused(
        invoke(
            &mut first,
            json!({"operation":"confirm_commit","token":interrupted.token,"snapshot":interrupted.snapshot.as_str()}),
        ),
        "preview_expired",
    );
    assert_empty(&mut first);
    assert!(!dest.exists());

    let mut second = RecoverySession::new();
    let a = admission
        .stage(&mut first, &dest, &backup, BACKUP, 0)
        .unwrap();
    let b = admission
        .stage(&mut second, &dest, &backup, BACKUP, 0)
        .unwrap();
    assert!(a.snapshot.as_str() != b.snapshot.as_str());
    store.insert(&dest, &a.snapshot).unwrap();
    // The first writer loses its acknowledgement. Another session attempts
    // its already prepared write at the same predecessor revision.
    refused(store.insert(&dest, &b.snapshot), "slot_occupied");
    refused(b.reconcile(&mut second, &dest), "different_winner");
    invoke(&mut second, json!({"operation":"cancel"})).unwrap();
    assert_empty(&mut second);
    assert_empty(&mut first);
    a.reconcile(&mut first, &dest).unwrap(); // no second write
    refused(a.reconcile(&mut first, &dest), "preview_expired");
    assert_eq!(status(&mut first)["public_key"], r.descriptor.root);
    assert!(fs::read(&dest).unwrap() == a.snapshot.as_bytes());
    assert!(fs::read(&cs).unwrap() == c.snapshot.as_bytes());
    unlock_verified(&cs, LOCAL, &c.descriptor, &network);
}
