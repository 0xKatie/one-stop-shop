# one-stop-shop

# System Scanning Toolkit (SST) & KB Hash Checker
This repository includes two PowerShell scripts developed to support system auditing and patch verification tasks in Windows environments:

## 📘 System Scanning Toolkit (SST.ps1)
A CLI-based tool for gathering system, network, and software inventory. 
Features include:
- Admin privilege detection
- System and network adapter info
- Installed software and SBOM listing
- Export options (CSV, JSON, TXT)
- Logging with output saved to a centralized `SST Files` directory

## 🔐 KB Hash Checker (kb-hash-check.ps1)
A PowerShell utility for validating the integrity of downloaded Microsoft update files. 
Features include:
- Interactive file path selection (supports Downloads folder)
- SHA1 and SHA256 hash comparison
- Safe verification before patch deployment

> All tools are read-only and designed for safe use in enterprise environments.

# Feedback and Pull Requests are welcomed and highly encouraged! 

---

# 🛠️ Roadmap & Background Projects

- [In Progress] Docs parser & ingestion feed
- [In Progress] Auditing network-active ports and last usage timestamps
- [Planned] Command Prompt and Bash compatible versions of tools
- [Planned] CVE-to-software correlation engine
- [Planned] Vendor site web scrapers
- [Planned] Threat feed integrations (MSRC, CISA KEV, etc.)
- [Planned] SBOM baseline generation and drift detection
- [Planned] GUI wrapper
