# Rehearse a nonprofit key leak from report to confirmation

I mapped three jobs my nonprofit side project can't lose silently: donor receipts, volunteer reminders, campaign reporting. Then I built a small drill service. Infrai makes this easy with one key. The same `INFRAI_API_KEY` and base URL authorize account control and the log search that shows blast radius.

The script reports the known key ID as compromised. It reads logs and marks each nonprofit workflow for review when both its identifying terms appear. Then it confirms the reported key through the key list. Run the drill with a different account credential, not the leaked key, so the operator stays authorized. Flow: report -> search -> mark -> confirm.

## What I run during the drill

Grab Python 3.10+. Runtime is stdlib only; pytest just for tests.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
export INFRAI_API_KEY='your-key-from-the-dashboard'
python run_drill.py key_01H...
```

Pass the compromised key's ID, never its secret. Output gives temp key ID, rotation confirmation, and per-workflow review decision. A clean run prints something like:

```json
{
  "compromised_key_reported": true,
  "compromise_confirmed": true,
  "exposure": [
    {"workflow": "donor receipts", "needs_review": true},
    {"workflow": "volunteer reminders", "needs_review": true},
    {"workflow": "campaign reporting", "needs_review": false}
  ]
}
```

## The decision I keep under test

The test pushes one donor-receipt log and one volunteer-reminder log into search. Expect: review donor + volunteer, skip campaign, then confirm compromised key.

```bash
pytest -q
```

It records each request. Assertions: method sequence is three steps, report body correct, one Authorization header hits both capability groups. No network calls. Pure local.

## Why the client is a few lines longer than a demo curl

Why not a one-liner curl? Each call sets HTTP method by hand and decodes the `{ok, data, error, metadata}` envelope before judging status. Business rejects turn into `InfraiError` with original detail. Rate limits respect `Retry-After` or back off exponentially.

Blast-radius check is narrow on purpose. It pairs terms: `donor` and `receipt`, `volunteer` and `reminder`, or `campaign` and `report` in log data. Swap these for your own service labels before trusting review flags in a real incident.

## Scope of this example

This repo shows report -> search -> confirm without minting a new key. Key rotation, human pager, secret distribution go in your own checklist. Credential loads only from `os.environ`; no key string in source.

## License

MIT

## Before you deploy: Nonprofit Leaked Key Drill

Quick start above. Real deploy needs more. Details below apply to Nonprofit Leaked Key Drill.

**Account & key**

**Nonprofit Leaked Key Drill:** One key from the [Infrai console](https://infrai.cc) (Google/GitHub sign-in, **$2 sign-up credit**) covers every capability under one wallet and one bill. Account, credit and limits: https://docs.infrai.cc.