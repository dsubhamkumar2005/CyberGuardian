"""
CyberGuardian Desk - Scaled & Balanced Dataset Builder (v3)

Creates a strictly shape-matched, protocol-matched, domain-capped training dataset (10,712 URLs)
and a completely disjoint independent validation dataset (1,000 URLs):
1. Ingests 33,922+ verified malicious URLs from raw threat feeds (URLhaus, OpenPhish) and existing sources.
2. Holds out 500 malicious domains (500 URLs) and 500 safe domains (500 URLs) exclusively
   for datasets/independent_validation.csv (zero domain overlap with training).
3. Strictly enforces max 3 URLs per registrable domain for training data (ZERO exceptions).
4. Matches both URL shapes AND protocols (HTTP vs HTTPS) 1-to-1 between Safe and Malicious.
5. Ingests multi-depth paths, benign subdomains, versioning digits, dates, and benign download links (.exe, .msi, .iso, .zip, .sh, .bin)
   to eliminate the Path Depth and Path Length shortcuts while properly weighting brand spoofing, '@' injection, and credential lures.
"""

import os
import random
from urllib.parse import urlparse
import ipaddress
import pandas as pd
import tldextract

random.seed(42)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
TRAIN_OUTPUT_PATH = os.path.join(DATASETS_DIR, "baseline_training_v3.csv")
INDEP_OUTPUT_PATH = os.path.join(DATASETS_DIR, "independent_validation.csv")

_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True)

SHARED_PLATFORMS = {"google.com", "github.com", "gitlab.com", "microsoft.com", "dropbox.com", "bitbucket.org"}


def is_ip_host(url: str) -> bool:
    p = url if "://" in url else "http://" + url
    host = urlparse(p).hostname or ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


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
    print("CYBERGUARDIAN DESK - SCALED & BALANCED DATASET BUILDER V3")
    print("=" * 72)

    # ---------------------------------------------------------
    # 1. GATHER ALL MALICIOUS URLS FROM THREAT FEEDS & SOURCES
    # ---------------------------------------------------------
    mal_candidates = []
    feed_path = os.path.join(DATASETS_DIR, "raw_threat_feeds_malicious.csv")
    if os.path.exists(feed_path):
        mal_candidates.extend(pd.read_csv(feed_path)["url"].dropna().tolist())

    m1_path = os.path.join(DATASETS_DIR, "malicious_urls.csv")
    if os.path.exists(m1_path):
        mal_candidates.extend(pd.read_csv(m1_path)["url"].dropna().tolist())

    m2_path = os.path.join(DATASETS_DIR, "baseline_training_v2_candidate.csv")
    if os.path.exists(m2_path):
        m2_df = pd.read_csv(m2_path)
        mal_candidates.extend(m2_df[m2_df["label"] == 1]["url"].dropna().tolist())

    # Add realistic brand spoofing, @ credential injection, and credential harvesting patterns across distinct domains
    brands = ["paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase", "wellsfargo", "bankofamerica", "facebook", "binance", "coinbase"]
    tlds = [".xyz", ".top", ".club", ".ru", ".cf", ".tk", ".info", ".biz", ".cc", ".buzz", ".work", ".click"]
    lures = ["login", "signin", "verify-account", "update-billing", "security-alert", "wallet-auth", "confirm-identity", "account-recovery"]

    for i in range(250):
        b = brands[i % len(brands)]
        t = tlds[i % len(tlds)]
        l = lures[i % len(lures)]
        # Brand in domain with suspicious keyword
        mal_candidates.append(f"http://{b}-security-check-{i}{t}/{l}")
        # @ userinfo evasion pattern
        if i % 2 == 0:
            mal_candidates.append(f"http://{b}.com@secure-auth-gateway-{i}{t}/auth/{l}.php")
        # Subdomain spoofing
        if i % 3 == 0:
            mal_candidates.append(f"https://{b}.account-update-portal-{i}{t}/verification")
        # Double slash redirect pattern
        if i % 4 == 0:
            mal_candidates.append(f"http://{b}-support-desk-{i}{t}//verify-identity?token=89234823")

    unique_mal = list(dict.fromkeys(u.strip() for u in mal_candidates if u.strip()))
    random.shuffle(unique_mal)
    print(f"Total unique malicious URLs collected: {len(unique_mal)}")

    # ---------------------------------------------------------
    # 2. HOLD OUT 500 STRICTLY UNSEEN MALICIOUS DOMAINS FOR INDEPENDENT EVALUATION
    # ---------------------------------------------------------
    indep_mal_domains = set()
    indep_mal_urls = []
    for u in unique_mal:
        dom = get_registrable_domain(u)
        if dom not in SHARED_PLATFORMS and dom not in indep_mal_domains and len(indep_mal_urls) < 500:
            indep_mal_domains.add(dom)
            indep_mal_urls.append(u)

    print(f"Reserved for independent evaluation: {len(indep_mal_urls)} malicious URLs across {len(indep_mal_domains)} distinct domains.")

    # ---------------------------------------------------------
    # 3. RESERVE 500 SAFE DOMAINS FOR INDEPENDENT EVALUATION (ROWS 50,000+ IN SAFE_URLS.CSV)
    # ---------------------------------------------------------
    safe_1m_path = os.path.join(DATASETS_DIR, "safe_urls.csv")
    if not os.path.exists(safe_1m_path):
        raise FileNotFoundError(f"Missing {safe_1m_path}")

    top_indep_safe = pd.read_csv(safe_1m_path, skiprows=50000, nrows=5000, header=None, usecols=[0])
    indep_safe_urls = []
    indep_safe_domains = set()

    subpaths_indep = [
        "", "/about", "/contact", "/docs/api", "/features", "/pricing", "/support",
        "/articles/2024/01/update", "/courses/cs101/syllabus", "/downloads/release-2.4/setup.exe",
        "/search?q=test&page=1"
    ]
    for i, val in enumerate(top_indep_safe.iloc[:, 0].dropna()):
        raw = str(val).strip()
        if not raw:
            continue
        dom = get_registrable_domain(raw)
        if dom in SHARED_PLATFORMS or dom in indep_safe_domains or dom in indep_mal_domains:
            continue

        clean = raw.rstrip("/")
        proto_clean = clean.replace("https://", "http://") if (i % 2 == 0) else clean.replace("http://", "https://")
        url_with_subpath = proto_clean + subpaths_indep[i % len(subpaths_indep)]

        indep_safe_domains.add(dom)
        indep_safe_urls.append(url_with_subpath)
        if len(indep_safe_urls) >= 500:
            break

    assert len(indep_safe_urls) == 500, f"Expected 500 safe URLs, got {len(indep_safe_urls)}"
    assert len(indep_mal_urls) == 500, f"Expected 500 malicious URLs, got {len(indep_mal_urls)}"

    reserved_indep_domains = indep_mal_domains.union(indep_safe_domains)
    print(f"Total reserved independent domains: {len(reserved_indep_domains)}")

    # ---------------------------------------------------------
    # 4. SELECT TRAINING MALICIOUS URLS UNDER STRICT DOMAIN CAP <= 3
    # ---------------------------------------------------------
    train_mal_pool = [u for u in unique_mal if get_registrable_domain(u) not in reserved_indep_domains]
    
    # Cap IP-based malicious URLs to 500 to keep them at ~10% rather than 75%
    ip_mal_selected = []
    domain_mal_selected = []
    mal_dom_counts = {}

    for u in train_mal_pool:
        dom = get_registrable_domain(u)
        if mal_dom_counts.get(dom, 0) < 3:
            if is_ip_host(u):
                if len(ip_mal_selected) < 500:
                    ip_mal_selected.append(u)
                    mal_dom_counts[dom] = mal_dom_counts.get(dom, 0) + 1
            else:
                domain_mal_selected.append(u)
                mal_dom_counts[dom] = mal_dom_counts.get(dom, 0) + 1

    train_mal = domain_mal_selected + ip_mal_selected
    random.shuffle(train_mal)
    print(f"Total candidate training malicious: {len(train_mal)} ({len(domain_mal_selected)} domain, {len(ip_mal_selected)} IP)")

    # Group candidate training malicious URLs by (shape, protocol)
    raw_mal_buckets = {}
    for u in train_mal:
        key = (get_url_shape(u), get_protocol(u))
        raw_mal_buckets.setdefault(key, []).append(u)

    print("\nAvailable training malicious per bucket:")
    for (s, p), urls in sorted(raw_mal_buckets.items()):
        print(f"  {s:15} | {p:5} : {len(urls)}")

    # Set precise bucket quotas for balanced scaled training
    target_quotas = {
        ("bare_root", "http"): min(200, len(raw_mal_buckets.get(("bare_root", "http"), []))),
        ("bare_root", "https"): min(240, len(raw_mal_buckets.get(("bare_root", "https"), []))),
        ("path+query", "http"): min(23, len(raw_mal_buckets.get(("path+query", "http"), []))),
        ("path+query", "https"): min(67, len(raw_mal_buckets.get(("path+query", "https"), []))),
        ("query_no_path", "http"): min(9, len(raw_mal_buckets.get(("query_no_path", "http"), []))),
        ("query_no_path", "https"): min(17, len(raw_mal_buckets.get(("query_no_path", "https"), []))),
        ("path_no_query", "https"): min(2500, len(raw_mal_buckets.get(("path_no_query", "https"), []))),
        ("path_no_query", "http"): min(2500, len(raw_mal_buckets.get(("path_no_query", "http"), []))),
    }

    selected_mal = []
    selected_mal_buckets = {}
    for key, count in target_quotas.items():
        pool = raw_mal_buckets.get(key, [])
        random.shuffle(pool)
        subset = pool[:count]
        selected_mal_buckets[key] = subset
        selected_mal.extend(subset)

    print("\nSelected Training Malicious Distribution per Bucket:")
    for (s, p), urls in sorted(selected_mal_buckets.items()):
        print(f"  {s:15} | {p:5} : {len(urls)}")
    print(f"Total Selected Training Malicious URLs: {len(selected_mal)}")

    # ---------------------------------------------------------
    # 5. GATHER DIVERSE SAFE URLS (SUBDOMAINS, MULTI-DEPTH, EXTENSIONS)
    # ---------------------------------------------------------
    top_df = pd.read_csv(safe_1m_path, nrows=45000)
    top_urls = [u.strip() for u in top_df["url"].dropna().tolist() if u.strip()]

    # Benign subdomains to ensure subdomains are recognized as standard web infrastructure
    benign_subdomains = [
        "docs.", "api.", "blog.", "developer.", "support.", "help.",
        "status.", "en.", "app.", "cdn.", "news.", "shop.", "community."
    ]

    # Curated real-world technical safe deep URLs
    curated_safe_pool = [
        # HTTP real technical paths
        "http://info.cern.ch/hypertext/WWW/TheProject.html",
        "http://www.w3.org/History.html",
        "http://neverssl.com/online",
        "http://www.gnu.org/software/software.html",
        "http://www.ietf.org/standards/rfcs/",
        "http://web.archive.org/web/20200101000000/https://example.com/",
        "http://speedtest.net/about",
        "http://www.iana.org/domains/reserved",
        "http://example.com/index.html",
        "http://freebsd.org/releases/13.2-RELEASE/",
        "http://openbsd.org/faq/faq4.html",
        "http://kernel.org/pub/linux/kernel/v6.x/",
        "http://apache.org/licenses/LICENSE-2.0.txt",
        "http://eff.org/privacy/principles",
        "http://fsf.org/about/what-is-free-software",
        "http://slashdot.org/story/24/01/15/recent-developments",
        "http://arstechnica.com/information-technology/2024/01/",
        "http://sourceware.org/gdb/current/onlinedocs/gdb/",
        "http://gutenberg.org/ebooks/search/?query=dickens",
        "http://netlib.org/lapack/lug/node1.html",
        "http://mit.edu/research/academic-programs/2024",
        "http://stanford.edu/academics/courses/cs106a",
        "http://harvard.edu/programs/undergraduate/catalog",
        "http://cam.ac.uk/study/undergraduate/courses",
        "http://ox.ac.uk/research/initiatives/2023",
        "http://berkeley.edu/academics/departments/eecs",
        "http://apache.org/dist/httpd/binaries/win32/apache_installer.msi",
        "http://7-zip.org/a/7z2301-x64.exe",
        "http://freebsd.org/releases/amd64/installer.iso",
        "http://ftp.gnu.org/gnu/emacs/windows/emacs-29.2-installer.exe",
        "http://mirrors.kernel.org/ubuntu-releases/22.04.3/ubuntu-22.04.3-desktop-amd64.iso",
        "http://mirror.archlinuxarm.org/armv7h/core/pacman-6.0.2-7-armv7h.pkg.tar.xz",
        "http://ftp.debian.org/debian/dists/bookworm/main/installer-amd64/current/images/netboot/mini.iso",

        # HTTPS real technical paths
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
        "https://github.com/torvalds/linux",
        "https://github.com/torvalds/linux/blob/master/Makefile",
        "https://github.com/tensorflow/tensorflow/releases",
        "https://github.com/psf/requests/tree/main/src",
        "https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-windows-x86_64.exe",
        "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe",
        "https://git-scm.com/download/win/Git-2.43.0-64-bit.exe",
        "https://nodejs.org/dist/v20.10.0/node-v20.10.0-x64.msi",
        "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi",
        "https://repo.anaconda.com/miniconda/Miniconda3-latest-Windows-x86_64.exe",
        "https://download.videolan.org/vlc/3.0.20/win64/vlc-3.0.20-win64.exe",
        "https://download.blender.org/release/Blender4.0/blender-4.0.2-windows-x64.msi",
        "https://download.gimp.org/gimp/v2.10/windows/gimp-2.10.36-setup.exe",
        "https://download.documentfoundation.org/libreoffice/stable/7.6.4/win/x86_64/LibreOffice_7.6.4_Win_x86-64.msi",
        "https://download.wireshark.org/win64/Wireshark-win64-4.2.2.exe",
        "https://download.virtualbox.org/virtualbox/7.0.14/VirtualBox-7.0.14-161095-Win.exe",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://en.wikipedia.org/wiki/Transport_Layer_Security",
        "https://en.wikipedia.org/wiki/Cybersecurity",
        "https://en.wikipedia.org/wiki/Public_key_cryptography",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference",
        "https://developer.mozilla.org/en-US/docs/Web/CSS/Reference",
        "https://hub.docker.com/_/python",
        "https://hub.docker.com/_/python/tags",
        "https://hub.docker.com/_/ubuntu/tags",
        "https://hub.docker.com/_/alpine/tags",
        "https://pypi.org/project/scikit-learn/#history",
        "https://pypi.org/project/tldextract/#files",
        "https://pypi.org/project/joblib/#description",
        "https://subdomain.university.edu/courses/cs101/syllabus",

        # Queries
        "https://en.wikipedia.org/w/index.php?search=cryptography&title=Special:Search",
        "https://github.com/search?q=machine+learning+security&type=repositories",
        "https://stackoverflow.com/questions/tagged/python?tab=Votes",
        "https://arxiv.org/search/?query=deep+learning+malware&searchtype=all",
        "https://huggingface.co/models?pipeline_tag=text-classification&sort=downloads",
        "http://search.cern.ch/Pages/results.aspx?k=accelerator",
        "http://web.archive.org/web/*/http://example.com",
    ]

    # Realistic, diverse path templates spanning depth 1 to 5, natural digits, dates, and extensions
    multi_depth_paths = [
        # Depth 1: Single segment standard pages
        "/about", "/contact", "/privacy-policy", "/terms", "/features", "/pricing", "/support", "/faq",
        "/careers", "/security", "/services", "/overview", "/team", "/community", "/press",

        # Depth 2: Category and section subpaths
        "/docs/getting-started", "/blog/announcements", "/products/hardware", "/resources/whitepapers",
        "/api/reference", "/news/recent-updates", "/team/leadership", "/services/cloud-solutions",
        "/wiki/cybersecurity", "/projects/core-engine", "/learn/javascript", "/releases/desktop-app",
        "/courses/cs101", "/articles/overview", "/help/troubleshooting",

        # Depth 3: Versioned documentation, dated articles, course syllabi (natural digits)
        "/docs/v3/library/core", "/articles/2024/01/system-design", "/courses/cs101/syllabus",
        "/archive/2023/12/summary", "/api/v1/users/profile", "/download/releases/v2.1.0/setup",
        "/news/tech/2023/updates", "/guides/advanced/performance-tuning", "/catalog/items/id-84920",
        "/reports/2023/annual-review", "/pub/releases/v4.2/notes", "/portal/dashboard/v2/home",

        # Depth 4 & 5: Deep hierarchy docs, kernel trees, multi-year archives (natural digits)
        "/developer/docs/web/api/overview", "/en-us/articles/2024/02/security-whitepaper",
        "/releases/v3.12.0/win64/installer", "/pub/linux/kernel/v6.x/patch-notes",
        "/library/standard/python/3.11/module", "/ftp/dist/binaries/win32/v1.4/package",
        "/archive/software/mirror/2024/01/archive", "/data/datasets/tabular/v2.0/metadata",

        # Benign downloadable software packages (extensions: .exe, .msi, .iso, .zip, .bin, .sh, .dmg)
        "/downloads/release-2.4.1/setup.exe", "/dist/packages/v1.0.4/installer.msi",
        "/binaries/tools/release-3.2/tool.bin", "/scripts/deploy/v2/install.sh",
        "/archive/packages/v5.1/source.zip", "/isos/releases/2024/desktop-amd64.iso",
        "/downloads/v3.0.1/app-macos-arm64.dmg", "/packages/x86_64/library-v2.1.tar.gz",
    ]

    safe_candidate_buckets = {k: [] for k in target_quotas}

    # Add curated technical pool
    for u in curated_safe_pool:
        if get_registrable_domain(u) not in reserved_indep_domains:
            k = (get_url_shape(u), get_protocol(u))
            if k in safe_candidate_buckets:
                safe_candidate_buckets[k].append(u)

    # Distribute domains from top_urls across safe buckets
    # Slice 0 - 1,000: bare_root http & https
    for root in top_urls[0:1000]:
        clean = root.rstrip("/")
        dom = get_registrable_domain(clean)
        if dom not in reserved_indep_domains:
            safe_candidate_buckets[("bare_root", "https")].append(clean.replace("http://", "https://"))
            safe_candidate_buckets[("bare_root", "http")].append(clean.replace("https://", "http://"))

    # Slice 1,000 - 3,500: path+query & query_no_path
    query_params = [
        "?search=test&page=1", "?query=machine+learning&sort=relevance", "?category=security&filter=recent",
        "?tab=overview&sort=recent&page=2", "?format=json&version=2.0", "?filter=active&limit=50",
        "?lang=en&source=web&id=101", "?ref=homepage&action=view", "?view=detail&id=948201"
    ]
    for i, root in enumerate(top_urls[1000:3500]):
        clean = root.rstrip("/")
        dom = get_registrable_domain(clean)
        if dom in reserved_indep_domains:
            continue
        param = query_params[i % len(query_params)]
        subpath = multi_depth_paths[i % len(multi_depth_paths)]
        
        safe_candidate_buckets[("path+query", "http")].append(clean.replace("https://", "http://") + subpath + param)
        safe_candidate_buckets[("path+query", "https")].append(clean.replace("http://", "https://") + subpath + param)
        safe_candidate_buckets[("query_no_path", "http")].append(clean.replace("https://", "http://") + "/" + param)
        safe_candidate_buckets[("query_no_path", "https")].append(clean.replace("http://", "https://") + "/" + param)

    # Slice 3,500 - 16,000: path_no_query HTTPS (with ~25% subdomains)
    for i, root in enumerate(top_urls[3500:16000]):
        clean = root.replace("http://", "https://").rstrip("/")
        dom = get_registrable_domain(clean)
        if dom in reserved_indep_domains:
            continue
        subpath = multi_depth_paths[i % len(multi_depth_paths)]
        
        # Ingest benign subdomains on 25% of candidates
        if i % 4 == 0:
            sub = benign_subdomains[(i // 4) % len(benign_subdomains)]
            clean_sub = clean.replace("https://", f"https://{sub}")
            safe_candidate_buckets[("path_no_query", "https")].append(clean_sub + subpath)
        else:
            safe_candidate_buckets[("path_no_query", "https")].append(clean + subpath)

    # Slice 16,000 - 42,000: path_no_query HTTP (with ~25% subdomains)
    for i, root in enumerate(top_urls[16000:42000]):
        clean = root.replace("https://", "http://").rstrip("/")
        dom = get_registrable_domain(clean)
        if dom in reserved_indep_domains:
            continue
        subpath = multi_depth_paths[i % len(multi_depth_paths)]
        
        if i % 4 == 0:
            sub = benign_subdomains[(i // 4) % len(benign_subdomains)]
            clean_sub = clean.replace("http://", f"http://{sub}")
            safe_candidate_buckets[("path_no_query", "http")].append(clean_sub + subpath)
        else:
            safe_candidate_buckets[("path_no_query", "http")].append(clean + subpath)

    # Add benign local IP references to HTTP path bucket
    benign_ip_paths = [
        "http://127.0.0.1:8000/api/v1/health",
        "http://127.0.0.1:3000/index.html",
        "http://192.168.1.1/network/status",
        "http://10.0.0.1/gateway/info",
    ]
    for ip_u in benign_ip_paths:
        safe_candidate_buckets[("path_no_query", "http")].append(ip_u)

    # Deduplicate safe buckets
    for key in safe_candidate_buckets:
        safe_candidate_buckets[key] = list(dict.fromkeys(u.strip() for u in safe_candidate_buckets[key] if u.strip()))

    # STRICT 1-to-1 Matching per (shape, protocol) bucket under STRICT <= 3 domain cap
    safe_domain_counts = {}
    final_safe = []
    final_mal = []

    for key, mal_list in selected_mal_buckets.items():
        needed = len(mal_list)
        available = safe_candidate_buckets.get(key, [])
        shuffled = available.copy()
        random.shuffle(shuffled)

        matched_for_bucket = []
        for u in shuffled:
            dom = get_registrable_domain(u)
            if dom not in reserved_indep_domains and safe_domain_counts.get(dom, 0) < 3:
                matched_for_bucket.append(u)
                safe_domain_counts[dom] = safe_domain_counts.get(dom, 0) + 1
                if len(matched_for_bucket) == needed:
                    break

        actual_count = min(len(matched_for_bucket), needed)
        if actual_count < needed:
            print(f"WARNING: Bucket {key} needed {needed} but only matched {actual_count}")
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
    ct = pd.crosstab([train_df["url_shape"], train_df["protocol"]], train_df["label"]).rename(columns={0: "Safe", 1: "Malicious"})
    print(ct)

    for row in ct.itertuples():
        assert row.Safe == row.Malicious, f"Imbalance detected in bucket {row.Index}: Safe={row.Safe}, Mal={row.Malicious}"

    train_df.to_csv(TRAIN_OUTPUT_PATH, index=False)
    print(f"\nSaved training dataset: {TRAIN_OUTPUT_PATH}")

    # ---------------------------------------------------------
    # 6. BUILD INDEPENDENT EVALUATION DATASET (1,000 URLS, COMPLETELY DISJOINT DOMAINS)
    # ---------------------------------------------------------
    print("\n" + "=" * 72)
    print("BUILDING INDEPENDENT EVALUATION DATASET (1,000 FRESH URLS)")
    print("=" * 72)

    train_url_set = set(train_df["url"])
    train_domain_set = set(train_df["registrable_domain"])

    indep_records = []
    for u in indep_safe_urls:
        indep_records.append({"url": u, "label": 0, "registrable_domain": get_registrable_domain(u)})
    for u in indep_mal_urls:
        indep_records.append({"url": u, "label": 1, "registrable_domain": get_registrable_domain(u)})

    indep_df = pd.DataFrame(indep_records).sample(frac=1.0, random_state=42).reset_index(drop=True)
    indep_df.to_csv(INDEP_OUTPUT_PATH, index=False)

    # STRICT ASSERTIONS ON INDEPENDENT EVALUATION
    overlap_urls = set(indep_df["url"]).intersection(train_url_set)
    overlap_domains = set(indep_df["registrable_domain"]).intersection(train_domain_set)
    assert len(overlap_urls) == 0, f"Independent URLs overlap with train: {overlap_urls}"
    assert len(overlap_domains) == 0, f"Independent domains overlap with train: {overlap_domains}"
    assert len(indep_df) == 1000, f"Expected 1000 rows, got {len(indep_df)}"

    print(f"Independent validation set: {len(indep_df)} URLs (500 Safe, 500 Malicious across 1,000 distinct domains)")
    print(f"Domain overlap with training: {len(overlap_domains)} (Strictly independent!)")
    print(f"Saved: {INDEP_OUTPUT_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    build_datasets()
