# CyberGuardian Desk — Member 1 (UI)

Desktop UI for **CyberGuardian Desk**: paste URL / QR / clipboard → features → ML verdict with reasons → local alert.

Privacy default: **everything stays on this PC**. History is local SQLite (`data/cyberguardian.sqlite`).

## Run (Windows)

```powershell
cd d:\Cursor\cyberguardian_desk
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Edit names, college, and team in `config.py` before the presentation.

## What this UI already does

- Scan pasted URLs and QR images (or pasted QR payload)
- Explainable reasons + engineered feature dump
- Opt-in **passive clipboard** URL watching
- Local history + analytics bars
- Privacy page (no cloud, SQLite, k-anonymity prefix helper)
- Hardware page ready for Member 5 (ESP32 stub + demo inject)
- Team / thank-you page

## Teammates

| Member | Owns | Plug-in file |
| --- | --- | --- |
| 1 | Desktop UI | `ui/` |
| 2 | AI/ML | `members/ml/classifier.py` |
| 3 | Input processing | `members/input_processing/extractor.py` |
| 4 | Backend / analytics | `members/backend/store.py` |
| 5 | Hardware | `members/hardware/device.py` |

Shared types: `core/contracts.py`. Glue: `core/pipeline.py`.

See **INTEGRATION.md**. When you have Member 2–5 code, paste it here and the UI can call it without a rewrite.

Optional extras (QR decode, serial, real sklearn model):

```powershell
pip install -r requirements-optional.txt
```
