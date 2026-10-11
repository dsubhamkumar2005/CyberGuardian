# CyberGuardian Desk

CyberGuardian Desk is a desktop application for scanning URLs, extracting security features, and displaying an ML-based verdict with reasons.

## Run on Windows

Activate the existing virtual environment and install dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

## Features

- URL scanning and validation
- QR and clipboard input support
- Production ML classification using the v3 model
- Risk information and explanations
- Local SQLite scan history

## Privacy

Scan history is stored locally on this PC.

## Machine Learning Documentation

The production classifier uses 23 cybersecurity features. The ML implementation, model evaluation methodology, and experimental details are documented in [README_ML.md](README_ML.md).

## Team Integration

The desktop UI and production ML classifier are integrated in this repository. The model and feature-order metadata are stored under `models/`.
