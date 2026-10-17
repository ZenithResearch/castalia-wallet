# Portable Data Is the Part of Web3 We Still Owe People

Status: draft article

Web3 made a simple promise: a person should be able to leave an application without leaving their digital life behind.

Most of the industry reduced that promise to portable money. A token can move between wallets. A public key can identify the same account on several networks. That is useful, but it is a thin slice of what people actually create online. Our histories, relationships, credentials, preferences, work, knowledge, rights, and communities usually remain trapped in the applications that collected them.

If switching software means starting over, the user does not meaningfully own the relationship. They may control an asset while renting the context that makes the asset useful.

## A wallet can carry more than assets

Castalia's `.castaway` format starts from a broader definition of a wallet. A compatible wallet is not only a keyring or a transaction prompt. It is a user-controlled boundary around a portable encrypted vault.

That vault can hold ordinary primitives and richer objects: identity data, a public credential, a public account descriptor, a knowledge note, a relationship, a receipt, a rights envelope, or an application preference. Each item retains a type defined through the Zenith Ontology rather than being reduced to a proprietary blob understood by one application.

This distinction matters. Byte portability lets someone copy a file. Semantic portability lets another application understand what the copied object is, preserve what it does not understand, and ask for consent before doing anything consequential with it.

```text
old model
application -> proprietary database -> export-shaped dead end

portable model
person -> encrypted typed vault -> wallet A / wallet B / future wallet
```

The applications can disagree about presentation. They can specialize. One may be a browser extension, another a native research workspace, and another a community client. They do not have to become the same product. They only have to preserve the user's objects and their meaning.

## Portability is not ambient authority

Putting many object types in one vault creates a dangerous temptation: treating every imported object as immediately active.

That would reproduce the same failure under a new name. Data is not automatically authority. A membership credential is not a login session, and a public account descriptor is not a signing key.

A portable vault therefore needs a hard authority boundary. Ordinary data can be rendered. Unknown data can be preserved opaquely when safe. Public credentials can be verified and presented through a separate ceremony. Private keys, recovery roots, mnemonics, bearer secrets, signing capabilities, and executable objects are not valid Castaway entries at all.

This is also why Castalia Wallet's `.castalia-recovery` file remains separate. It is a narrow encrypted copy of one root signing authority and the dedicated portable recovery artifact. A `.castaway` file never contains an authority capsule. The two formats are not interchangeable, and neither one creates membership by itself.

## The ontology is the interoperability layer

File formats often fail because they standardize syntax without standardizing meaning. Two applications can parse the same JSON and still disagree about what an object represents, which relationships matter, or which policy controls disclosure.

The Zenith Ontology supplies that missing semantic layer. A vault entry points to a versioned type. Relationships are typed edges rather than labels inferred from interface copy. Provenance and rights travel with governed objects. A wallet that cannot render a type can preserve its authenticated bytes without pretending to understand it.

The result is not one universal application. It is a shared language that lets specialized applications cooperate without claiming ownership of the user's whole world.

## A more grounded Web3

Portable encrypted data does not need to put personal information on a blockchain. Most private data should never be published to a global ledger. Networks remain useful for public commitments, receipts, revocation, discovery, settlement, and shared state. The vault remains with the person.

That division produces a more grounded architecture:

- private context stays in a user-controlled encrypted vault;
- public credentials and commitments can be independently verified;
- applications request narrow projections instead of ingesting the entire person;
- signing authority remains in wallet custody and its dedicated recovery artifact;
- communities can recognize shared objects without becoming the custodian of every private detail; and
- leaving one application does not erase years of accumulated meaning.

This is the Web3 promise worth recovering. Not that every interaction becomes a financial transaction, and not that every datum becomes public, but that people can carry their identity, knowledge, relationships, and rights across software boundaries without asking the previous platform for permission.

Tokens proved that digital objects can be portable. The harder task is making a digital life portable without making it public, unsafe, or semantically empty. That is what `.castaway` is meant to explore.
