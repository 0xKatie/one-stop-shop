import csv
import os
import re
import sys
import string
import unicodedata
from datetime import datetime

csv.field_size_limit(sys.maxsize)

# === Logging counters and entries ===
log_entries = []
num_rows_processed = 0
num_errors = 0
num_skipped_rows = 0
num_unicode_replacements = 0

# === Utility: Null detection ===
def is_null_like(text):
    return text.strip().lower() in [
        "", "--", "---", "- -", "na", "n/a", "null", "none", "not applicable"
    ]

# === Smart Cleaner ===
def smart_clean(text):
    if text is None or is_null_like(text):
        return ""
    text = text.replace("'", "").replace('"', "")  # Remove apostrophes completely
    allowed = set(string.ascii_letters + string.digits + " -|.@")
    cleaned = "".join(char if char in allowed else " " for char in text)
    cleaned = re.sub(r"\s+", " ", cleaned)   # Collapse multiple spaces into one
    return cleaned.strip().lower()

# === Normalize address before punctuation is stripped ===
def normalize_address_component(text):
    if text is None:
        return ""
    text = text.lower().strip()
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
        "c/o": "courtesy of"
    }
    for key, val in suffixes.items():
        text = re.sub(rf"\b{re.escape(key)}\b", val, text)
    return smart_clean(text)

# === Final cleaner ===
def clean_field(value):
    global num_unicode_replacements
    if not value:
        return ""

    try:
        # Strip unicode accents
        value = unicodedata.normalize("NFKD", value)
        value = value.encode("ascii", "ignore").decode("ascii")
        num_unicode_replacements += 1
    except Exception:
        pass

    return smart_clean(value)

    # Remove specific unwanted characters
    value = value.translate(str.maketrans({
        "™": "", "®": "", "°": "", "©": "", "—": "",
        "•": "", "±": "", "¹": "", "²": "", "³": "", "×": ""
    }))

    # Remove apostrophes completely
    value = value.replace("'", "")

    # Collapse multiple spaces
    value = re.sub(r"\s{2,}", " ", value)

    return value.strip().lower()

# === Main processing ===
def main():
    global num_rows_processed, num_errors, num_skipped_rows

    input_path = input("Enter the full path to the input file: ").strip()
    base_name = input("Enter a name for the output file (without extension): ").strip()
    output_ext = input("Output as .txt or .csv? ").strip().lower()
    if output_ext not in ["txt", "csv"]:
        print("Invalid extension. Defaulting to .csv")
        output_ext = "csv"

    output_path = f"{base_name}.{output_ext}"

    # Show input file info
    file_size_kb = os.path.getsize(input_path) / 1024
    print(f"\nInput file: {input_path}")
    print(f"File type: .{input_path.split('.')[-1]}")
    print(f"File size: {file_size_kb:.2f} KB")

    try:
        with open(input_path, newline="", encoding="cp1252", errors="replace") as infile, \
             open(output_path, "w", newline="", encoding="utf-8") as outfile:

            reader = csv.reader(infile, delimiter="|")
            writer = csv.writer(outfile, delimiter="|" if output_ext == "txt" else ",")

            header = next(reader)
            writer.writerow([col.strip() for col in header])

            for row_idx, row in enumerate(reader, start=2):
                try:
                    if len(row) != len(header):
                        num_skipped_rows += 1
                        log_entries.append(f"[SKIPPED ROW] Line {row_idx}: Field count mismatch (expected {len(header)}, got {len(row)})\nRow: {row}")
                        continue

                    cleaned_row = [clean_field(val) for val in row]
                    writer.writerow(cleaned_row)
                    num_rows_processed += 1

                except Exception as e:
                    num_errors += 1
                    log_entries.append(f"[ERROR] Line {row_idx}: {e}")

    except csv.Error as e:
        print(f"\n[CSV ERROR] {e}")
        return

    # Output file info
    output_size_kb = os.path.getsize(output_path) / 1024
    print(f"\nOutput file: {output_path}")
    print(f"Output file size: {output_size_kb:.2f} KB")

    # Summary
    print("\n=== Summary ===")
    print(f"Rows processed: {num_rows_processed}")
    print(f"Skipped rows: {num_skipped_rows}")
    print(f"Errors: {num_errors}")
    print(f"Unicode replacements: {num_unicode_replacements}")

    # Save log
    log_file = base_name + ".log.txt"
    with open(log_file, "w", encoding="utf-8") as logf:
        logf.write(f"Log generated on {datetime.now().isoformat()}\n\n")
        for entry in log_entries:
            logf.write(entry + "\n")
    print(f"\nLog file saved to: {log_file}")

if __name__ == "__main__":
    main()
