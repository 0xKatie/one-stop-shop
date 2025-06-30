import csv

input_file = "mdr-foi-2024-clean.txt"
output_file = "mdr-foi-2024-clean-trimmed.txt"

# The columns you want to keep (case-insensitive match)
columns_to_keep = [
    'mdr_report_key',
    'event_key',
    'report_number',
    'report_source_code',
    'manufacturer_link_flag',
    'product_problem_flag',
    'manufacturer_contact_exchange',
    'device_date_of_manufacture',
    'distributor_name',
    'manufacturer_name',
    'type_of_report',
    'pma_pmn_number',
    'summary_report'
]

# Normalize for matching
columns_to_keep_lower = [c.lower() for c in columns_to_keep]

with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8", newline='') as outfile:
    reader = csv.reader(infile, delimiter='|')
    writer = csv.writer(outfile, delimiter='|')

    header = next(reader)
    header_lower = [col.strip().lower() for col in header]

    # Determine indexes of columns to keep
    keep_indexes = [i for i, col in enumerate(header_lower) if col in columns_to_keep_lower]
    trimmed_header = [header[i] for i in keep_indexes]

    writer.writerow(trimmed_header)

    for row in reader:
        trimmed_row = [row[i] if i < len(row) else '' for i in keep_indexes]
        writer.writerow(trimmed_row)

print(f"Trimmed file saved as {output_file}")
