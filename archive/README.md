# CyberGuardian Desk - Historical Archive

This folder archives legacy experimental scripts, intermediate datasets, and deprecated model iterations:
- **`legacy_src/` (`archive/src/`)**: Deprecated training and evaluation scripts superseded by the V3 domain-separated pipeline.
- **`legacy_models/` (`archive/models/`)**: Deprecated models (V1, rebuilt, and candidate models) superseded by `models/url_classifier_v3.pkl`.
- **`legacy_features/` (`archive/features/`)**: Deprecated feature matrices superseded by `features/features_v3.csv` and `features/features_independent_validation.csv`.
- **`legacy_results/` (`archive/results/`)**: Older benchmark logs and diagnostic results.
- **`legacy_datasets/` (`archive/datasets/`)**: Older un-balanced or un-capped datasets superseded by `datasets/baseline_training_v3.csv`.

The active, production-grade pipeline lives exclusively under `src/`, `models/`, `features/`, `results/`, and `datasets/`.

