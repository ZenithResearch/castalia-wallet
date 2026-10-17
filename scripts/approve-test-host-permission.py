"""Approve one observed native Chrome host prompt in the disposable CI display only."""
import json
import os
import sys
import time
from pathlib import Path
import pyatspi

host = sys.argv[1]
if (sys.platform != "linux" or os.environ.get("BUILDKITE") != "true"
        or host not in {"issuer-a.castalia.test", "issuer-b.castalia.test",
                        "issuer-untrusted.castalia.test", "issuer-mismatch.castalia.test",
                        "127.0.0.1", "legacy-fixture.castalia.test"}
        or not os.environ.get("DISPLAY")):
    raise SystemExit("Disposable Linux issuer lane required")

def collect(node, depth=0, budget=None):
    if budget is None:
        budget = [3000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 30:
        return []
    try:
        showing = node.getState().contains(pyatspi.STATE_SHOWING)
        result = [(node, node.getRoleName(), node.name or "")] if showing else []
        for child in node:
            result.extend(collect(child, depth + 1, budget))
        return result
    except Exception:
        return []

last = []
applications = []
for _ in range(80):
    desktop = pyatspi.Registry.getDesktop(0)
    applications = [app.name for app in desktop]
    for app in desktop:
        if "chrom" not in (app.name or "").lower():
            continue
        for window in app:
            nodes = collect(window)
            labels = "\n".join(name for _, _, name in nodes)
            last = [{"role": role, "name": name} for _, role, name in nodes]
            # Never synthesize a permission grant or accept an unrelated dialog.
            if host not in labels or "Castalia" not in labels:
                continue
            buttons = [node for node, role, name in nodes
                       if role == "push button" and name == "Allow"]
            if len(buttons) != 1:
                continue
            state = buttons[0].getState()
            if not state.contains(pyatspi.STATE_ENABLED) or not state.contains(pyatspi.STATE_SENSITIVE):
                continue
            action = buttons[0].queryAction()
            names = [action.getName(i) for i in range(action.nActions)]
            print(json.dumps({"host": host, "nativeActions": names}), flush=True)
            clicks = [i for i in range(action.nActions)
                      if action.getName(i).lower() in {"click", "press", "activate"}]
            if len(clicks) != 1 or not action.doAction(clicks[0]):
                continue
            print(json.dumps({"nativeHostPermission": host, "action": "Allow",
                              "method": "AT-SPI observed native Chrome prompt"}))
            raise SystemExit(0)
    time.sleep(0.25)
Path("build/buildkite-verify/native-permission-diagnostic.json").write_text(json.dumps({"applications": applications, "visibleNodes": last}, indent=2))
raise SystemExit("Expected native Chrome permission prompt was not observed")
