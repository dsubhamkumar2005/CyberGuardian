
import os
import pandas as pd
import tldextract

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_PATH = os.path.join(
    BASE_DIR, "features", "features_domain.csv"
)

OUTPUT_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

df = pd.read_csv(INPUT_PATH)

df["domain"] = df["url"].apply(
    lambda url: tldextract.extract(str(url)).top_domain_under_public_suffix
)

print("=" * 60)
print("CYBERGUARDIAN DESK - DATASET AUDIT")
print("=" * 60)

print(f"\nTotal URLs: {len(df)}")
print(f"Unique URLs: {df['url'].nunique()}")
print(f"Unique registrable domains: {df['domain'].nunique()}")

print("\nLabel counts:")
print(df["label"].value_counts().rename(
    index={0: "Safe", 1: "Malicious"}
))

# Domains that have both safe and malicious labels.
labels_per_domain = df.groupby("domain")["label"].nunique()
conflicting_domains = labels_per_domain[labels_per_domain > 1].index

conflicts = df[df["domain"].isin(conflicting_domains)].sort_values(
    ["domain", "label", "url"]
)

print(f"\nDomains with conflicting labels: {len(conflicting_domains)}")

if len(conflicting_domains):
    print(conflicts[["domain", "url", "label"]].to_string(index=False))
    conflicts.to_csv(
        os.path.join(OUTPUT_DIR, "domain_label_conflicts.csv"),
        index=False,
    )
else:
    print("No conflicting domain labels found.")

# Exact URLs duplicated across the original dataset.
duplicate_urls = df[df["url"].duplicated(keep=False)]

print(f"\nRows involved in duplicate URLs: {len(duplicate_urls)}")

if not duplicate_urls.empty:
    duplicate_urls.to_csv(
        os.path.join(OUTPUT_DIR, "duplicate_urls.csv"),
        index=False,
    )

# Show how many domains belong to each class.
domain_class_counts = (
    df.groupby("label")["domain"]
    .nunique()
    .rename(index={0: "Safe", 1: "Malicious"})
)

print("\nUnique domains represented in each class:")
print(domain_class_counts)

print("\nAudit completed.")
print("Review any conflict or duplicate CSV files created in results/.")
