# IOC Extractor (Go)

A small blue-team tool written in Go that extracts Indicators of Compromise (IOCs)
from text or log files.

The tool detects:
- IPv4 addresses  
- Domains  
- URLs  
- Hashes (MD5, SHA1, SHA256)

It also deobfuscates common patterns (hxxp, [.] ), removes duplicates,
and exports results to CSV and JSON.

---

## Features
- Extract IP, domain, URL and hash IOCs  
- Deobfuscation support (hxxp → http, [.] → .)  
- Deduplication  
- CSV and JSON export  
- Can read from file or stdin  

---

## Installation

```bash
git clone https://github.com/USERNAME/ioc-extractor-go.git
cd ioc-extractor-go
go mod init ioc-extractor-go
