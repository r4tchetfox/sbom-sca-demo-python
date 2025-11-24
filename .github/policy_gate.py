#!/usr/bin/env python3
import json, sys, datetime
SEV_BLOCK = {"High","Critical"}

def active(exc):
    try:
        return datetime.date.today() <= datetime.date.fromisoformat(exc.get("until",""))
    except:
        return False

def load_exc(path=".github/exceptions.json"):
    try:
        with open(path) as f:
            data = json.load(f)
        return { (e["cve"], e["component"]): e for e in data.get("entries",[]) }
    except:
        return {}

exc = load_exc()
with open(sys.argv[1]) as f:
    rep = json.load(f)

viol = []
for m in rep.get("matches",[]):
    sev = (m.get("vulnerability") or {}).get("severity") or m.get("severity")
    cve = (m.get("vulnerability") or {}).get("id") or "UNKNOWN"
    comp = (m.get("artifact") or {}).get("name")
    if sev in SEV_BLOCK and not active(exc.get((cve,comp),{})):
        viol.append((cve, comp, sev))

if viol:
    print("Policy Gate: BLOCK")
    for c,p,s in viol:
        print(f"- {c} @ {p} ({s})")
    sys.exit(1)

print("Policy Gate: PASS")
sys.exit(0)
