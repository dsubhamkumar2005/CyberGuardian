# How other members plug into the UI

The window never imports “secret” internals. It only uses:

```text
GuardianPipeline.scan(ScanRequest) -> ScanResult
LocalStore.analytics() / recent_scans()
HardwareBridge.connect() / poll() / inject_demo_payload()
```

Keep method names. You may replace the bodies.

## Member 2 — `members/ml/classifier.py`

```python
class MLClassifier:
    def predict(self, features: FeatureSet) -> tuple[VerdictLabel, float, str, list[str]]:
        ...
```

Load your `joblib` Random Forest / Logistic Regression here. Map class probabilities to `VerdictLabel`. Put SHAP / feature-contribution strings into `reasons`.

Do **not** put a neural net behind this unless the team agrees — the pitch already justifies classical models (speed, CPU-only, explainability).

## Member 3 — `members/input_processing/extractor.py`

Replace:

- `extract()` — URL normalize, clipboard parse
- `decode_qr()` — camera or OpenCV/pyzbar
- `engineer_features()` — the real lexical feature vector your model was trained on

Feature **keys must match** what Member 2’s model expects. If your vectorizer is TF-IDF, return it inside `FeatureSet.values` (or add `FeatureSet.vector` in `core/contracts.py` and teach `MLClassifier` to read it). Tell Member 1 if the contract needs a new field.

## Member 4 — `members/backend/store.py`

SQLite path is `config.DB_PATH`. You can add tables (users, false-positive flags, exports) as long as `save_scan`, `recent_scans`, and `analytics` still work.

## Member 5 — `members/hardware/device.py`

Wire `serial` JSON from ESP32. When a URL arrives, Member 1 already calls:

```python
pipeline.scan(ScanRequest(source="hardware", raw_input=url))
```

from the Hardware page demo button. Point `poll()` at the same path.

## What I still need from you

Paste (or drop files for) any of:

1. Member 2: training script, `model.joblib`, feature list  
2. Member 3: QR/camera code and feature list  
3. Member 4: extra analytics queries or schema  
4. Member 5: ESP32 firmware serial format  

I will bind them into this UI without changing the screens unless a new control is required.
