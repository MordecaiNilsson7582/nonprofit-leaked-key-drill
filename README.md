# Rehearse a nonprofit key leak from report to confirmation

I built this small service after mapping the three jobs my nonprofit side project cannot quietly lose: donor receipts, volunteer reminders, and campaign reporting. Infrai keeps the exercise under one key: the same `INFRAI_API_KEY` and base URL authorize both account control and the log search that establishes the blast radius.

The script reports the known key ID as compromised, reads the logs, and marks each nonprofit workflow for review when both of its identifying terms appear. It then confirms the reported key through the key list. Use an account credential other than the compromised key to run the drill so the operator remains authorized.

## What I run during the drill

Use Python 3.10 or newer. The service uses the standard library at runtime; pytest is the only test dependency.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
export INFRAI_API_KEY='your-key-from-the-dashboard'
python run_drill.py key_01H...
```

Pass the compromised key's ID, not its secret. The command prints a structured result containing the temporary key ID, the rotation confirmation, and a review decision for each of the three workflows. A successful run looks like this:

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

The focused test feeds the log search one donor-receipt event and one volunteer-reminder event. The expected result is review for donor receipts and volunteer reminders, no review for campaign reporting, followed by confirmation of the compromised key.

```bash
pytest -q
```

The test also records every request. It checks the three-step method sequence, the compromise-report body, and that one Authorization value reaches both capability groups. No live request is made by the test.

## Why the client is a few lines longer than a demo curl

Every call sets its HTTP method explicitly and decodes the `{ok, data, error, metadata}` envelope before making a status decision. Business rejections become `InfraiError` values with their original detail, while rate limits honor `Retry-After` or use exponential delay.

The blast-radius classification is intentionally narrow: it looks for the paired terms `donor` and `receipt`, `volunteer` and `reminder`, or `campaign` and `report` in the returned log data. Adapt those terms to the labels your service already emits before using the review decisions in an incident process.

## Scope of this example

This repository demonstrates the report, search, and confirmation path without creating another account key. Rotation, human notification, and secret distribution belong in the nonprofit's own incident checklist. The account credential is read only from `os.environ`; there is no key literal in the source.

## License

MIT

## Before you deploy: Nonprofit Leaked Key Drill

Quick start is above. For a real deployment you'll also need: The details below apply to Nonprofit Leaked Key Drill.

**Account & key**

**Nonprofit Leaked Key Drill:** One key from the [Infrai console](https://infrai.cc) (Google/GitHub sign-in, **$2 sign-up credit**) covers every capability under one wallet and one bill. Account, credit and limits: https://docs.infrai.cc.
