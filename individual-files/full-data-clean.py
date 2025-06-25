import csv
import sys
import re
import string
import unicodedata

csv.field_size_limit(sys.maxsize)

# === Configuration ===
preview_mode = False  # Set to True for preview
if preview_mode:
    input_path = "contact_addresses.txt"
    output_path = "preview_cleaned_data.csv"
    num_preview_rows = 100
else:
    input_path = "contact_addresses.txt"
    output_path = "cleaned_data.csv"

# === Utility: Null detection ===
def is_null_like(text):
    return text.strip().lower() in [
        "", "-", "--", "---", "- -", "na", "n/a", "null", "none", "not applicable"
    ]

# === Smart Cleaner ===
def smart_clean(text):
    if text is None or is_null_like(text):
        return ""

    # Strip quotes early
    text = text.replace('"', '').replace("'", '')

    # Keep alphanumerics, hyphen, pipe, and space
    allowed = set(string.ascii_letters + string.digits + " -|")
    cleaned = "".join(char if char in allowed else " " for char in text)

    # Collapse multiple spaces
    cleaned = re.sub(r"\s+", " ", cleaned)

    return cleaned.strip().lower()

# === Clean field (wrapper) ===
def clean_field(text):
    return smart_clean(text)

def strip_unicode_accents(text):
    # Converts "résumé" -> "resume", "ü" -> "u"
    if not isinstance(text, str):
        return ""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join([c for c in nfkd if not unicodedata.combining(c)])

# === Normalize address before punctuation is stripped ===
def normalize_address_component(text):
    if text is None:
        return ""

    fixes = {
        "p.o. box": "po box",
        "hwy": "highway",
        "ave": "avenue",
        "blvd": "boulevard",
        "ln": "lane",
        "rd": "road",
        "dr": "drive",
        "pl": "place",
        "n.e.": "northeast",
        "n.w.": "northwest",
        "s.e.": "southeast",
        "s.w.": "southwest",
        "n.": "north",
        "s.": "south",
        "e.": "east",
        "w.": "west"
    }

    text = text.lower().strip()
    for key, val in fixes.items():
        text = re.sub(rf"\b{re.escape(key)}\b", val, text)

    return smart_clean(text)

# === Normalize company names ===
def normalize_company_name(text):
    if text is None:
        return ""
    text = text.lower().strip()
    suffixes = {
        "corp": "corporation",
        "inc": "incorporated",
        "l.l.c": "llc",
        "ltd": "limited",
        "co": "company",
        "c/o": "courtesy of"
    }
    for key, val in suffixes.items():
        text = re.sub(rf"\b{re.escape(key)}\b", val, text)

    return smart_clean(text)

# === Route normalization by column ===
def normalize_by_column(col_name, value):
    col = col_name.lower()

    if any(keyword in col for keyword in ["address", "street", "mail", "direction", "zip"]):
        return normalize_address_component(value)
    elif "name" in col and any(word in col for word in ["company", "business", "org", "entity", "firm", "corp", "estab", "agency", "enterpr", "group"]):
        return normalize_company_name(value)
    else:
        return clean_field(value)

# === File processing ===
with open(input_path, "r", encoding="utf-8", errors="ignore") as infile, \
     open(output_path, "w", newline='', encoding="utf-8") as outfile:

    reader = csv.reader(infile, delimiter='|', quotechar=None)
    writer = csv.writer(outfile)

    header = next(reader)
    extended_header = []
    for h in header:
        extended_header.append(f"original_{h}")
        extended_header.append(f"cleaned_{h}")
    writer.writerow(extended_header)

    for i, row in enumerate(reader):
        if preview_mode and i >= num_preview_rows:
            break
        cleaned_row = []
        for h, val in zip(header, row):
            original = val.strip()
            cleaned = normalize_by_column(h, val)
            cleaned_row.extend([original, cleaned])
        writer.writerow(cleaned_row)

print(f"Output written to: {output_path}")
