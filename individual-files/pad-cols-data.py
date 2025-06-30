input_file = "contacts-gudid-clean.txt"
output_file = "contacts-clean-fixed.txt"
expected_columns = 4  # or 5 if you still have `primarydi`

with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8") as outfile:
    for i, line in enumerate(infile):
        line = line.strip()
        parts = line.split("|")

        # Pad with empty fields if not enough columns
        while len(parts) < expected_columns:
            parts.append("")

        # Truncate extra columns just in case
        if len(parts) > expected_columns:
            parts = parts[:expected_columns]

        outfile.write("|".join(parts) + "\n")

print("File cleaned and saved as", output_file)
