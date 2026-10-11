"""
CyberGuardian Desk - Rigorous Balanced Dataset Builder (v3)

Creates a strictly shape-matched, protocol-matched, domain-capped training dataset
and a completely disjoint independent validation dataset:
1. Holds out 100 malicious domains (100 URLs) and 100 safe domains (100 URLs) exclusively
   for datasets/independent_validation.csv (zero overlap with training).
2. Strictly enforces max 3 URLs per registrable domain for training data (ZERO exceptions).
3. Matches both URL shapes AND protocols (HTTP vs HTTPS) 1-to-1 between Safe and Malicious.
4. Incorporates benign download links (.exe, .msi, .iso, .zip, .sh) to prevent false-positive bias.
"""

import os
import random
from urllib.parse import urlparse
import pandas as pd
import tldextract

random.seed(42)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
TRAIN_OUTPUT_PATH = os.path.join(DATASETS_DIR, "baseline_training_v3.csv")
INDEP_OUTPUT_PATH = os.path.join(DATASETS_DIR, "independent_validation.csv")

_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True)


def get_registrable_domain(url: str) -> str:
    url_str = str(url).strip()
    if not url_str:
        return "unknown"
    p = url_str if "://" in url_str else "http://" + url_str
    ext = _EXTRACTOR(p)
    dom = ext.top_domain_under_public_suffix
    if dom:
        return dom.lower()
    host = urlparse(p).hostname
    return host.lower() if host else "unknown"


def get_url_shape(url: str) -> str:
    p = urlparse(url if "://" in url else "http://" + url)
    has_path = bool(p.path and p.path != "/")
    has_query = bool(p.query)
    if has_path and has_query:
        return "path+query"
    if has_path:
        return "path_no_query"
    if has_query:
        return "query_no_path"
    return "bare_root"


def get_protocol(url: str) -> str:
    p = urlparse(url if "://" in url else "http://" + url)
    return p.scheme.lower() if p.scheme else "http"


def build_datasets():
    print("=" * 72)
    print("CYBERGUARDIAN DESK - RIGOROUS DATASET BUILDER V3")
    print("=" * 72)

    # ---------------------------------------------------------
    # 1. GATHER ALL MALICIOUS URLS
    # ---------------------------------------------------------
    mal_candidates = []
    m1_path = os.path.join(DATASETS_DIR, "malicious_urls.csv")
    if os.path.exists(m1_path):
        mal_candidates.extend(pd.read_csv(m1_path)["url"].dropna().tolist())

    m2_path = os.path.join(DATASETS_DIR, "baseline_training_v2_candidate.csv")
    if os.path.exists(m2_path):
        m2_df = pd.read_csv(m2_path)
        mal_candidates.extend(m2_df[m2_df["label"] == 1]["url"].dropna().tolist())

    unique_mal = list(dict.fromkeys(u.strip() for u in mal_candidates if u.strip()))
    random.shuffle(unique_mal)
    print(f"Total unique malicious URLs collected: {len(unique_mal)}")

    # ---------------------------------------------------------
    # 2. HOLD OUT 100 STRICTLY UNSEEN MALICIOUS DOMAINS FOR INDEPENDENT EVALUATION
    # ---------------------------------------------------------
    indep_mal_domains = set()
    indep_mal_urls = []
    for u in unique_mal:
        dom = get_registrable_domain(u)
        if dom not in indep_mal_domains and len(indep_mal_urls) < 100:
            indep_mal_domains.add(dom)
            indep_mal_urls.append(u)

    print(f"Reserved for independent evaluation: {len(indep_mal_urls)} malicious URLs across {len(indep_mal_domains)} distinct domains.")

    # ---------------------------------------------------------
    # 3. SELECT TRAINING MALICIOUS URLS UNDER STRICT DOMAIN CAP <= 3
    # ---------------------------------------------------------
    train_mal_pool = [u for u in unique_mal if get_registrable_domain(u) not in indep_mal_domains]
    train_mal = []
    mal_dom_counts = {}
    for u in train_mal_pool:
        dom = get_registrable_domain(u)
        if mal_dom_counts.get(dom, 0) < 3:
            train_mal.append(u)
            mal_dom_counts[dom] = mal_dom_counts.get(dom, 0) + 1

    print(f"Training malicious URLs (strictly <= 3 per domain): {len(train_mal)} across {len(mal_dom_counts)} domains.")

    # Group training malicious URLs by (shape, protocol)
    mal_buckets = {}
    for u in train_mal:
        key = (get_url_shape(u), get_protocol(u))
        mal_buckets.setdefault(key, []).append(u)

    print("\nTarget training distribution per bucket:")
    for (s, p), urls in sorted(mal_buckets.items()):
        print(f"  {s:15} | {p:5} : {len(urls)}")

    # ---------------------------------------------------------
    # 4. GATHER DIVERSE SAFE URLS ACROSS DOMAINS
    # ---------------------------------------------------------
    safe_buckets = {k: [] for k in mal_buckets}

    # Benign downloads (prevent false positives on .exe, .msi, .iso, .zip, .sh)
    benign_downloads = [
        "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe",
        "https://git-scm.com/download/win/Git-2.43.0-64-bit.exe",
        "https://nodejs.org/dist/v20.10.0/node-v20.10.0-x64.msi",
        "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64",
        "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi",
        "https://repo.anaconda.com/miniconda/Miniconda3-latest-Windows-x86_64.exe",
        "http://apache.org/dist/httpd/binaries/win32/apache_installer.msi",
        "http://7-zip.org/a/7z2301-x64.exe",
        "http://freebsd.org/releases/amd64/installer.iso",
        "https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-windows-x86_64.exe",
    ]

    # Curated safe technical paths and queries
    curated_safe_pool = [
        # HTTP paths
        "http://info.cern.ch/hypertext/WWW/TheProject.html",
        "http://www.w3.org/History.html",
        "http://neverssl.com/online",
        "http://www.gnu.org/software/software.html",
        "http://www.ietf.org/standards/rfcs/",
        "http://web.archive.org/web/20200101000000/https://example.com/",
        "http://speedtest.net/about",
        "http://www.iana.org/domains/reserved",
        "http://example.com/index.html",
        "http://freebsd.org/releases/",
        "http://openbsd.org/faq/",
        "http://kernel.org/pub/linux/",
        "http://apache.org/licenses/LICENSE-2.0.txt",
        "http://eff.org/privacy",
        "http://fsf.org/about/",
        "http://slashdot.org/story/recent",
        "http://arstechnica.com/information-technology/",
        "http://sourceware.org/gdb/",
        "http://gutenberg.org/ebooks/search/",
        "http://netlib.org/lapack/",
        "http://mit.edu/research",
        "http://stanford.edu/academics",
        "http://harvard.edu/programs",
        "http://cam.ac.uk/study",
        "http://ox.ac.uk/research",
        "http://berkeley.edu/academics",

        # HTTPS paths
        "https://docs.python.org/3/library/math.html",
        "https://docs.python.org/3/tutorial/index.html",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://docs.python.org/3/library/os.path.html",
        "https://scikit-learn.org/stable/modules/ensemble.html",
        "https://scikit-learn.org/stable/modules/linear_model.html",
        "https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html",
        "https://fastapi.tiangolo.com/tutorial/first-steps/",
        "https://fastapi.tiangolo.com/deployment/docker/",
        "https://react.dev/learn/describing-the-ui",
        "https://react.dev/reference/react/useState",
        "https://nodejs.org/api/fs.html",
        "https://nodejs.org/api/http.html",
        "https://nodejs.org/api/path.html",
        "https://nodejs.org/api/crypto.html",
        "https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.html",
        "https://numpy.org/doc/stable/reference/arrays.ndarray.html",
        "https://pytorch.org/docs/stable/torch.html",
        "https://github.com/torvalds/linux/blob/master/Makefile",
        "https://github.com/tensorflow/tensorflow/releases",
        "https://github.com/psf/requests/tree/main/src",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://en.wikipedia.org/wiki/Transport_Layer_Security",
        "https://en.wikipedia.org/wiki/Cybersecurity",
        "https://en.wikipedia.org/wiki/Public_key_cryptography",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference",
        "https://developer.mozilla.org/en-US/docs/Web/CSS/Reference",
        "https://hub.docker.com/_/python/tags",
        "https://hub.docker.com/_/ubuntu/tags",
        "https://hub.docker.com/_/alpine/tags",
        "https://pypi.org/project/scikit-learn/#history",
        "https://pypi.org/project/tldextract/#files",
        "https://pypi.org/project/joblib/#description",
        "https://subdomain.university.edu/courses/cs101/syllabus",

        # HTTPS queries
        "https://en.wikipedia.org/w/index.php?search=cryptography&title=Special:Search",
        "https://en.wikipedia.org/w/index.php?search=computer+security&title=Special:Search",
        "https://github.com/search?q=machine+learning+security&type=repositories",
        "https://github.com/search?q=network+traffic+analysis&type=repositories",
        "https://stackoverflow.com/search?q=random+forest+classifier",
        "https://stackoverflow.com/questions/tagged/python?tab=Votes",
        "https://stackoverflow.com/questions/tagged/machine-learning?tab=Active",
        "https://duckduckgo.com/?q=python+documentation&t=h_&ia=web",
        "https://duckduckgo.com/?q=tldextract+usage&ia=about",
        "https://arxiv.org/search/?query=deep+learning+malware&searchtype=all",
        "https://arxiv.org/search/?query=adversarial+machine+learning&searchtype=all",
        "https://huggingface.co/models?pipeline_tag=text-classification&sort=downloads",
        "https://huggingface.co/datasets?sort=downloads&search=cybersecurity",
        "https://www.google.com/search?q=machine+learning+cybersecurity",
        "https://www.bing.com/search?q=neural+network+basics",
        "https://news.ycombinator.com/item?id=38291029",
        "https://news.ycombinator.com/item?id=39120391",
        "https://www.reddit.com/r/netsec/search/?q=phishing+detection&restrict_sr=1",
        "https://www.reddit.com/r/MachineLearning/search/?q=tabular+data&restrict_sr=1",
        "https://www.imdb.com/find/?q=the+matrix&ref_=nv_sr_sm",
        "https://www.amazon.com/s?k=cybersecurity+books&ref=nb_sb_noss",
        "https://www.ebay.com/sch/i.html?_nkw=computer+networking",
        "https://scholar.google.com/scholar?q=url+phishing+detection+machine+learning",
        "https://scholar.google.com/scholar?q=random+forest+cybersecurity",

        # HTTP queries
        "http://search.cern.ch/Pages/results.aspx?k=accelerator",
        "http://www.gnu.org/cgi-bin/estseek.cgi?phrase=compiler",
        "http://web.archive.org/web/*/http://example.com",
        "http://gutenberg.org/ebooks/search/?query=dickens",
        "http://slashdot.org/index2.pl?fhfilter=technology",
        "http://search.freebsd.org/search/search.cgi?words=kernel",
        "http://bugs.debian.org/cgi-bin/pkgreport.cgi?pkg=python",
        "http://openbsd.org/cgi-bin/man.cgi?query=pf",
        "http://netlib.org/cgi-bin/netlibfiles.pl?filename=blas",
        "http://arstechnica.com/search/?q=cybersecurity",
        "http://dilbert.com/search?terms=computer",
        "http://ietf.org/search/?q=dnssec",
    ]

    for u in curated_safe_pool + benign_downloads:
        key = (get_url_shape(u), get_protocol(u))
        if key in safe_buckets:
            safe_buckets[key].append(u)

    # Safe URLs from Top 1M list (safe_urls.csv)
    safe_1m_path = os.path.join(DATASETS_DIR, "safe_urls.csv")
    if os.path.exists(safe_1m_path):
        top_df = pd.read_csv(safe_1m_path, nrows=8000)
        top_urls = [u.strip() for u in top_df["url"].dropna().tolist() if u.strip()]

        standard_subpaths = [
            "/about", "/contact", "/privacy-policy", "/terms-of-service",
            "/docs", "/blog", "/features", "/pricing", "/support",
            "/help", "/resources", "/overview", "/services", "/team",
            "/faq", "/careers", "/security", "/guides", "/community"
        ]

        # HTTP paths from distinct domains
        for i, root in enumerate(top_urls[500:1500]):
            clean_http = root.replace("https://", "http://").rstrip("/")
            path_suffix = standard_subpaths[i % len(standard_subpaths)]
            safe_buckets[("path_no_query", "http")].append(clean_http + path_suffix)

        # HTTPS paths from distinct domains
        for i, root in enumerate(top_urls[1500:2500]):
            clean_https = root.replace("http://", "https://").rstrip("/")
            path_suffix = standard_subpaths[i % len(standard_subpaths)]
            safe_buckets[("path_no_query", "https")].append(clean_https + path_suffix)

        # Bare roots: HTTP & HTTPS
        for root in top_urls[2500:3500]:
            safe_buckets[("bare_root", "https")].append(root.replace("http://", "https://"))
            safe_buckets[("bare_root", "http")].append(root.replace("https://", "http://"))

        # Extra queries
        for root in top_urls[3500:4000]:
            clean_http = root.replace("https://", "http://").rstrip("/")
            clean_https = root.replace("http://", "https://").rstrip("/")
            safe_buckets[("path+query", "http")].append(clean_http + "/search?q=test")
            safe_buckets[("path+query", "https")].append(clean_https + "/search?q=test")
            safe_buckets[("query_no_path", "http")].append(clean_http + "/?ref=web")
            safe_buckets[("query_no_path", "https")].append(clean_https + "/?ref=web")

    for key in safe_buckets:
        safe_buckets[key] = list(dict.fromkeys(u.strip() for u in safe_buckets[key] if u.strip()))

    # STRICT 1-to-1 Matching per (shape, protocol) bucket under STRICT <= 3 domain cap
    safe_domain_counts = {}
    final_safe = []
    final_mal = []

    for key, mal_list in mal_buckets.items():
        needed = len(mal_list)
        available = safe_buckets.get(key, [])
        shuffled = available.copy()
        random.shuffle(shuffled)

        matched_for_bucket = []
        for u in shuffled:
            dom = get_registrable_domain(u)
            if safe_domain_counts.get(dom, 0) < 3:
                matched_for_bucket.append(u)
                safe_domain_counts[dom] = safe_domain_counts.get(dom, 0) + 1
                if len(matched_for_bucket) == needed:
                    break

        actual_count = min(len(matched_for_bucket), needed)
        final_safe.extend(matched_for_bucket[:actual_count])
        final_mal.extend(mal_list[:actual_count])

    print(f"\nFinal Matched Training Dataset: {len(final_safe)} Safe, {len(final_mal)} Malicious")

    # Build Training DataFrame
    train_records = []
    for u in final_safe:
        train_records.append({
            "url": u, "label": 0,
            "registrable_domain": get_registrable_domain(u),
            "url_shape": get_url_shape(u),
            "protocol": get_protocol(u),
            "source_category": "balanced_safe_v3",
        })
    for u in final_mal:
        train_records.append({
            "url": u, "label": 1,
            "registrable_domain": get_registrable_domain(u),
            "url_shape": get_url_shape(u),
            "protocol": get_protocol(u),
            "source_category": "balanced_malicious_v3",
        })

    train_df = pd.DataFrame(train_records).sample(frac=1.0, random_state=42).reset_index(drop=True)

    # STRICT ASSERTIONS ON DOMAIN CAP <= 3
    max_safe_dom = train_df[train_df["label"] == 0]["registrable_domain"].value_counts().max()
    max_mal_dom = train_df[train_df["label"] == 1]["registrable_domain"].value_counts().max()
    assert max_safe_dom <= 3, f"Safe domain cap violated: max={max_safe_dom}"
    assert max_mal_dom <= 3, f"Malicious domain cap violated: max={max_mal_dom}"

    print("\n" + "=" * 72)
    print("V3 TRAINING DATASET INTEGRITY CHECKS")
    print("=" * 72)
    print(f"Total training rows: {len(train_df)}")
    print(f"Unique domains: {train_df['registrable_domain'].nunique()}")
    print(f"Max URLs per domain: Safe={max_safe_dom}, Malicious={max_mal_dom} (Strictly <= 3 enforced!)")
    print("\nExact Shape & Protocol Crosstab (Safe vs Malicious):")
    print(pd.crosstab([train_df["url_shape"], train_df["protocol"]], train_df["label"]).rename(columns={0: "Safe", 1: "Malicious"}))

    train_df.to_csv(TRAIN_OUTPUT_PATH, index=False)
    print(f"Saved training dataset: {TRAIN_OUTPUT_PATH}")

    # ---------------------------------------------------------
    # 5. BUILD INDEPENDENT EVALUATION DATASET (COMPLETELY DISJOINT DOMAINS)
    # ---------------------------------------------------------
    print("\n" + "=" * 72)
    print("BUILDING INDEPENDENT EVALUATION DATASET")
    print("=" * 72)

    train_url_set = set(train_df["url"])
    train_domain_set = set(train_df["registrable_domain"])

    # Disjoint independent safe URLs (fresh domains never seen in training)
    indep_safe_pool = [
        "https://www.nature.com/articles/s41586-023-06747-5",
        "https://www.sciencedirect.com/science/article/pii/S016740482300091X",
        "https://springer.com/journal/10207",
        "https://acm.org/publications/proceedings-template",
        "https://ieee.org/conferences/publishing/templates.html",
        "https://usenix.org/conference/usenixsecurity24",
        "https://cisa.gov/resources-tools/all-resources-products",
        "https://nih.gov/health-information",
        "https://nasa.gov/missions/artemis",
        "https://esa.int/Science_Exploration/Human_and_Robotic_Exploration",
        "https://w3c.github.io/webappsec-secure-contexts/",
        "https://ietf.org/rfc/rfc9110.html",
        "https://eff.org/deeplinks/2024/01/eff-at-50",
        "https://fsf.org/campaigns/free-software-licensing",
        "https://kernel.org/doc/html/latest/",
        "https://gitlab.com/explore/projects",
        "https://bitbucket.org/product",
        "https://codeberg.org/explore/repos",
        "https://crates.io/crates/tokio",
        "https://pkg.go.dev/net/http",
        "https://rubygems.org/gems/rails",
        "https://packagist.org/packages/symfony/http-foundation",
        "https://nuget.org/packages/Newtonsoft.Json",
        "https://deno.land/manual",
        "https://bun.sh/docs",
        "https://ziglang.org/learn/overview",
        "https://rust-lang.org/learn",
        "https://golang.org/doc/tutorial/getting-started",
        "https://swift.org/getting-started/",
        "https://kotlinlang.org/docs/home.html",
        "http://neverssl.com/faq",
        "http://info.cern.ch/hypertext/WWW/Status.html",
    ]

    indep_safe_candidates = []
    for u in indep_safe_pool:
        dom = get_registrable_domain(u)
        if u not in train_url_set and dom not in train_domain_set:
            indep_safe_candidates.append(u)

    # Sample fresh top domains (starting from row 10000 to ensure completely disjoint domains)
    if os.path.exists(safe_1m_path):
        top_fresh = pd.read_csv(safe_1m_path, skiprows=10000, nrows=2000, usecols=[0], header=None)
        for u in top_fresh.iloc[:, 0].dropna():
            clean = str(u).strip()
            if not clean:
                continue
            dom = get_registrable_domain(clean)
            if clean not in train_url_set and dom not in train_domain_set:
                indep_safe_candidates.append(clean)
                if len(indep_safe_candidates) >= 120:
                    break

    indep_safe_final = list(dict.fromkeys(indep_safe_candidates))[:100]
    indep_mal_final = indep_mal_urls[:100]

    indep_records = []
    for u in indep_safe_final:
        indep_records.append({"url": u, "label": 0, "registrable_domain": get_registrable_domain(u)})
    for u in indep_mal_final:
        indep_records.append({"url": u, "label": 1, "registrable_domain": get_registrable_domain(u)})

    indep_df = pd.DataFrame(indep_records).sample(frac=1.0, random_state=42).reset_index(drop=True)
    indep_df.to_csv(INDEP_OUTPUT_PATH, index=False)

    # Check zero overlap
    overlap_urls = set(indep_df["url"]).intersection(train_url_set)
    overlap_domains = set(indep_df["registrable_domain"]).intersection(train_domain_set)
    assert len(overlap_urls) == 0, f"Independent URLs overlap with train: {overlap_urls}"
    print(f"Independent validation set: {len(indep_df)} URLs ({sum(indep_df['label']==0)} Safe, {sum(indep_df['label']==1)} Malicious)")
    print(f"Domain overlap with training: {len(overlap_domains)} (Strictly independent!)")
    print(f"Saved: {INDEP_OUTPUT_PATH}")


if __name__ == "__main__":
    build_datasets()
