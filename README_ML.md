# CyberGuardian Desk: Pure Machine Learning URL Security Classifier

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.9.0-orange)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An auditable, high-performance machine learning pipeline designed to detect malicious, phishing, and malware distribution URLs using **23 static cybersecurity features**, rigorous **domain-separated cross-validation**, and **1-to-1 shape and protocol matching**.

---

## 1. Executive Summary & Novelty

Many published URL classifiers suffer from severe methodological flaws:
1. **The "Path Length / Path Depth Trap"**: Malicious URLs from threat feeds (e.g. URLhaus, OpenPhish) often have deep paths, whereas naive benign datasets (e.g., Alexa/Tranco top domains) consist solely of shallow homepages (`https://example.com/`). Models learn to classify *any* URL with a path as malicious, leading to catastrophic false alarm rates on legitimate deep-link URLs.
2. **Domain Leakage**: Splitting datasets randomly (`train_test_split`) leaks URLs from the same domain into both training and test folds. The model memorizes domain identities rather than generalizable attack features, producing artificially inflated test scores (~99%) that collapse in real-world deployment.
3. **Protocol Imbalance**: Malicious feeds often contain unencrypted HTTP URLs, while benign feeds are predominantly HTTPS. Without balanced protocols within each shape category, models simply learn "HTTP = bad, HTTPS = good".
4. **Hardcoded Whitelist Bypass Fallacy**: Hardcoding safety rules for reputable domains (e.g., `google.com`, `.edu`, `.gov`) masks classifier flaws and creates severe vulnerabilities against open redirects, subpath compromises, and user-generated content attacks.

### How CyberGuardian Resolves These:
- **Strict Shape & Protocol Matching**: Benign training URLs are sampled across 8 distinct buckets matching exact URL shapes (bare domain, simple path, multi-directory deep path, query strings) and protocols (HTTP vs HTTPS 1-to-1).
- **Strict Domain Capping**: Enforces a maximum limit of **3 URLs per registrable domain** across the entire training set (zero exceptions), preventing high-volume domains from dominating the loss function.
- **Domain-Separated 5-Fold Cross-Validation**: Evaluates models using `StratifiedGroupKFold` on registrable domains under the Public Suffix List (PSL). Domains in test folds are strictly unseen during training.
- **Disjoint Independent Holdout Evaluation**: Features an external benchmark of **1,000 URLs across 1,000 unique domains** (500 safe, 500 malicious) with **strictly zero overlap** with training data.
- **Pure Machine Learning Decisions**: No hardcoded whitelist bypasses. Domain reputation labels (e.g. Global Authority, Accredited Institutional Domain) are purely informational context. The verdict is strictly computed by the statistical ML inference model against the decision threshold.
- **Canonical Normalization**: Standardizes URL strings, schemes, and userinfo before feature extraction, ensuring that `google.com` and `http://google.com` produce identical feature representations.
- **Safe Input Rejection**: Rejects malformed or non-web schemes (`javascript:`, `data:`, `file:`) with explicit `0.0` confidence and `Invalid / Unsupported` status.

---

## 2. The 23 Extracted Security Features

| Category | Feature Name | Type | Description |
| :--- | :--- | :--- | :--- |
| **Lexical & Structural** | `length` | Integer | Total character length of normalized URL |
| | `path_length` | Integer | Character length of the URL path component |
| | `query_length` | Integer | Character length of query parameters |
| | `subdomain_count` | Integer | Number of subdomain hierarchy levels |
| | `num_subdirectories` | Integer | Count of path directory delimiters (`/`) |
| | `uses_ip` | Binary | `1` if host is a raw IPv4 or bracketed IPv6 address |
| | `has_https` | Binary | `1` if protocol scheme is HTTPS |
| | `non_standard_port` | Binary | `1` if non-standard network port is explicitly defined |
| **Statistical & Information Theory** | `special_char_count` | Integer | Count of non-alphanumeric characters |
| | `shannon_entropy` | Float | Information entropy (randomness) of full URL |
| | `domain_entropy` | Float | Shannon entropy of hostname (detects DGA domains) |
| | `path_entropy` | Float | Shannon entropy of path + query string |
| | `num_digits` | Integer | Count of numerical digits (0-9) |
| | `digit_ratio` | Float | Ratio of digits to total URL length |
| | `num_hyphens` | Integer | Count of hyphens (`-`), frequent in typo-squatting |
| **Threat Intelligence & Signatures** | `has_at_symbol` | Binary | `1` if RFC 3986 userinfo `@` symbol is present (credential injection) |
| | `has_double_slash_redirect` | Binary | `1` if `//` exists in path (redirect evasion) |
| | `is_shortened` | Binary | `1` if domain is a known URL shortener service |
| | `has_suspicious_keywords` | Binary | `1` if credential harvesting lure keywords present |
| | `is_high_risk_tld` | Binary | `1` if TLD has statistically elevated registration abuse |
| | `is_institutional_tld` | Binary | `1` if verified institutional registrar (`.edu`, `.gov`, `.mil`) |
| | `brand_impersonation` | Binary | `1` if popular brand token appears in deceptive host/subdomain |
| | `has_executable_extension` | Binary | `1` if path targets payload extension (`.exe`, `.bin`, `.apk`, etc.) |

---

## 3. Independent Model Selection & Empirical Results

### A. 5-Fold Domain-Separated Cross-Validation (`features_v3.csv`, 4,972 URLs)

Evaluated on 4,530 unique registrable domains using `StratifiedGroupKFold`:

| Model Architecture | OOF Accuracy | Malicious Precision | Malicious Recall | Malicious F1 |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest** | 96.71% | 98.34% | 95.05% | 96.65% |
| **HistGradientBoosting** | 97.38% | 97.55% | 97.18% | 97.34% |
| **MLP (Neural Network)** | 94.67% | 95.02% | 94.33% | 94.66% |
| **Logistic Regression** | 89.28% | 89.47% | 89.06% | 89.26% |

### B. Held-Out Independent Generalization (`independent_validation.csv`, 1,000 URLs)

Evaluated on **1,000 completely unseen domains** (500 Safe, 500 Malicious) with **zero domain overlap**:

| Metric | Random Forest (Selected Model) | HistGradientBoosting | Difference / Impact |
| :--- | :---: | :---: | :--- |
| **Holdout Accuracy** | **94.40%** | 90.20% | **+4.20% RF advantage** |
| **Holdout F1-Score** | **94.67%** | 91.01% | **+3.66% RF advantage** |
| **Attack Recall** | **99.40%** (497 / 500) | 99.20% (496 / 500) | Near-identical coverage |
| **False Positives (FPR)** | **53 (10.60%)** | 94 (18.80%) | **RF cuts false alarms by 44%** |
| **False Negatives (Misses)** | **3 (0.60%)** | 4 (0.80%) | RF misses 25% fewer attacks |
| **HTTP Subset Accuracy** | **96.50%** | 93.63% | +2.87% |
| **HTTPS Subset Accuracy** | **92.36%** | 86.89% | **+5.47% RF advantage** |

### Why Random Forest Was Selected for Production:
While HistGradientBoosting slightly outperformed on the training CV splits, **Random Forest demonstrated superior generalization on the independent validation set**. Random Forest slashed the False Positive rate from 18.80% down to 10.60% (44% reduction in false alarms on legitimate domains) while achieving a higher attack recall (99.40%). For security operations, minimizing false positives on legitimate business sites without compromising detection efficacy is essential.

---

## 4. Repository Structure

```
Project - cybersec/
Gö£GöÇGöÇ datasets/
Göé   Gö£GöÇGöÇ baseline_training_v3.csv          # 4,972 shape-matched, protocol-matched training URLs
Göé   Gö£GöÇGöÇ independent_validation.csv        # 1,000 disjoint held-out URLs (0 domain overlap)
Göé   Gö£GöÇGöÇ raw_threat_feeds_malicious.csv    # 33,999 live threat feed URLs (URLhaus + OpenPhish)
Göé   Gö£GöÇGöÇ safe_urls.csv                     # Benign URL source pool
Göé   GööGöÇGöÇ malicious_urls.csv                # Initial seed threat URLs
Gö£GöÇGöÇ features/
Göé   Gö£GöÇGöÇ features_v3.csv                   # 23-feature training matrix (4,972 rows)
Göé   GööGöÇGöÇ features_independent_validation.csv # 23-feature holdout matrix (1,000 rows)
Gö£GöÇGöÇ models/
Göé   Gö£GöÇGöÇ url_classifier_v3.pkl             # Production Random Forest model (scikit-learn 1.9.0)
Göé   Gö£GöÇGöÇ feature_order_v3.json             # Exact 23-feature alignment schema
Göé   GööGöÇGöÇ model_metadata_v3.json            # Model card, hyperparams, & validation metrics
Gö£GöÇGöÇ results/
Göé   Gö£GöÇGöÇ domain_cv_v3_fold_metrics.csv     # Fold-by-fold cross-validation metrics
Göé   Gö£GöÇGöÇ domain_cv_v3_oof_predictions.csv  # Out-of-fold predictions for all candidates
Göé   Gö£GöÇGöÇ domain_cv_v3_summary.csv          # Summary cross-validation statistics
Göé   Gö£GöÇGöÇ independent_validation_comparison.csv # RF vs HistGradientBoosting comparison
Göé   Gö£GöÇGöÇ independent_validation_results.csv    # Production model holdout metrics
Göé   Gö£GöÇGöÇ random_forest_v3_cv_importance.csv    # Feature importance ranking
Göé   GööGöÇGöÇ random_forest_v3_errors.csv       # Audited classification errors
Gö£GöÇGöÇ src/
Göé   Gö£GöÇGöÇ fetch_threat_feeds.py             # Verified TLS threat feed ingestion engine
Göé   Gö£GöÇGöÇ build_balanced_dataset_v3.py      # Shape-matched, protocol-matched dataset builder
Göé   Gö£GöÇGöÇ feature_extractor.py              # Canonical URL normalizer & 23-feature extractor
Göé   Gö£GöÇGöÇ generate_features_v3.py           # Feature matrix generation pipeline
Göé   Gö£GöÇGöÇ evaluate_candidate_cv_v3.py       # Domain CV, candidate evaluation & model selection
Göé   Gö£GöÇGöÇ analyze_candidate_v3_errors.py    # Out-of-fold error analysis tool
Göé   Gö£GöÇGöÇ classifier.py                     # Production inference engine (pure ML)
Göé   Gö£GöÇGöÇ classify.py                       # User CLI & programmatic classification entrypoint
Göé   GööGöÇGöÇ interactive_test.py               # Edge-case and regression test suite
Gö£GöÇGöÇ archive/                              # Safely archived legacy v1/v2 iterations
Gö£GöÇGöÇ requirements.txt                      # Locked runtime dependencies
Gö£GöÇGöÇ .gitignore                            # Excluded caches, venvs, and secrets
GööGöÇGöÇ README.md                             # Comprehensive technical documentation
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Windows PowerShell, macOS zsh, or Linux bash

### Setup Instructions
```bash
# Clone the repository
git clone <repo-url>
cd "Project - cybersec"

# Create and activate a virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install locked dependencies
pip install -r requirements.txt
```

---

## 6. End-to-End Execution Pipeline

To reproduce the entire pipeline from live threat intelligence feeds to production deployment:

### Step 1: Ingest Threat Feeds
Downloads live malware and phishing feeds with strict TLS verification and records dataset provenance:
```bash
python src/fetch_threat_feeds.py
```

### Step 2: Build Balanced Datasets
Constructs shape-matched, protocol-matched training and holdout datasets under strict domain caps:
```bash
python src/build_balanced_dataset_v3.py
```

### Step 3: Extract Feature Matrices
Extracts the 23 cybersecurity features into matrices:
```bash
python src/generate_features_v3.py
```

### Step 4: Run Domain Cross-Validation & Select Model
Executes 5-Fold `StratifiedGroupKFold` on all candidates, evaluates both top candidates on the independent held-out set, applies the selection rule, and compiles `models/url_classifier_v3.pkl`:
```bash
python src/evaluate_candidate_cv_v3.py
```

### Step 5: Analyze Classification Errors
Audits False Positives and False Negatives and outputs feature importances:
```bash
python src/analyze_candidate_v3_errors.py
```

### Step 6: Run Regression & Edge-Case Benchmark
Tests benign homepages, deep links, executable downloads, IPv6 hosts, IP URLs, credential lures, and malformed schemes:
```bash
python src/interactive_test.py
```

---

## 7. Inference & API Usage

### Command-Line Interface (CLI)

Classify an arbitrary URL:
```bash
python src/classify.py "http://paypal-security-alert.com//verify-account?token=89234823"
```

Output:
```text
URL        : http://paypal-security-alert.com//verify-account?token=89234823
Verdict    : Malicious
Confidence : 97.20% (P(Malicious)=0.97, P(Safe)=0.03)
Threshold  : 0.5
Reputation : Standard Public Domain
Indicators :
  - Brand impersonation signature observed: recognized brand token in deceptive host/subdomain context
  - Redirect evasion indicator: contains '//' in URL path
  - Observed credential harvesting lure keyword (e.g. login, verify, wallet, signin)
  - Elevated domain character randomness (3.81 entropy bits), characteristic of DGA
```

Custom decision threshold (e.g. threshold = 0.70 for high precision):
```bash
python src/classify.py "https://example.com/login" 0.70
```

### Python Programmatic API

```python
from classifier import classify

# Inspect a URL
result = classify("https://subdomain.university.edu/courses/cs101/syllabus")

print(f"Verdict: {result['verdict']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Reputation: {result['domain_reputation']}")
print("Observed Indicators:", result["reasons"])
```

### Handling Non-Web Schemes
Malformed schemes such as `javascript:alert(1)` or `data:text/html,...` are rejected gracefully:
```text
URL        : javascript:alert(1)
Verdict    : Invalid / Unsupported
Confidence : 0.00% (P(Malicious)=0.00, P(Safe)=0.00)
Indicators :
  - Input validation rejected: Unsupported URL scheme 'javascript' (only HTTP/HTTPS supported)
```

---

## 8. Operational Limitations & Security Governance

1. **Pickle Security**: Serialized model files (`.pkl`) can execute arbitrary code if untrusted. Only load models from verified repository commits. Never deserialize user-supplied `.pkl` files.
2. **Static Lexical Feature Boundary**: The 23 features evaluate the static structure and lexical patterns of the URL string. A zero-day attack hosted on an uncompromised, clean corporate domain (e.g., standard SharePoint file or clean Google Form lure) without lexical anomalies cannot be detected solely through static URL inspection. Complete defense-in-depth requires pairing this engine with content inspection, DOM analysis, and TLS certificate telemetry.
3. **Decision Threshold Tuning**:
   - `threshold = 0.50` (Default): Balanced operation (99.40% recall, 10.60% FPR on unseen domains).
   - `threshold = 0.70`: High-confidence blocking mode; minimizes false alarms in sensitive corporate web gateways.
   - `threshold = 0.30`: High-security inspection mode; flags borderline URLs for secondary sandbox emulation.

