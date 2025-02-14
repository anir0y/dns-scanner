# DNS Record Scanner

DNS Record Scanner is a Go-based tool to scan and analyze SPF, DKIM, and DMARC records for domains. It provides detailed results, warnings for misconfigurations, and a summary of findings. The tool supports scanning a single domain, multiple domains from a file, and saving results to a CSV file.

## Features

- **SPF Check**: Detects SPF records and warns about weak configurations (e.g., missing `~all` or `-all`).
- **DKIM Check**: Auto-enumerates common DKIM selectors to find DKIM records.
- **DMARC Check**: Detects DMARC records and warns about weak policies (e.g., `p=none`).
- **Summary Report**: Provides a concise summary of findings for each domain.
- **CSV Output**: Saves results in a structured CSV format for further analysis.
- **Flexible Input**: Supports scanning a single domain or multiple domains from a file.

## Installation

### Prerequisites

- Go 1.18 or higher installed on your system.
- Internet access to perform DNS lookups.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/anir0y/dns-scanner.git
   cd dns-scanner
   ```

2. Build the binary:
   ```bash
   go build -o dns-scanner .
   ```

3. Run the tool:
   ```bash
   ./dns-scanner
   ```

Alternatively, you can run the tool directly using `go run`:
```bash
go run main.go [flags]
```

## Usage

The tool supports the following flags:

| Flag | Description | Example |
|------|-------------|---------|
| `-d` | Scan a single domain | `./dns-scanner -d example.com` |
| `-f` | Scan domains from a file (one domain per line) | `./dns-scanner -f domains.txt` |
| `-o` | Save results to a CSV file | `./dns-scanner -f domains.txt -o results.csv` |

If no flags are provided, the tool will display a help menu with usage instructions.

## Examples

### 1. Scan a Single Domain
```bash
./dns-scanner -d example.com
```

### 2. Scan Domains from a File
Create a file `domains.txt` with one domain per line:
```
example.com
test.com
another-example.com
```

Run the tool:
```bash
./dns-scanner -f domains.txt
```

### 3. Save Results to a CSV File
```bash
./dns-scanner -f domains.txt -o results.csv
```

### 4. Help Menu
If you run the tool without any flags, it will display the help menu:
```bash
./dns-scanner
```

Output:
```
Usage:
  dns-scanner [flags]

Flags:
  -d string
        Scan a single domain (e.g., example.com)
  -f string
        Scan domains from a file (one domain per line)
  -o string
        Save results to a CSV file

Example Usage:
  dns-scanner -d example.com
  dns-scanner -f domains.txt
  dns-scanner -f domains.txt -o results.csv
```

## Sample Output

### Console Output
```plaintext
Scanning domain: example.com
SPF: v=spf1 include:_spf.google.com ~all
DKIM: Found (google): v=DKIM1; k=rsa; p=<public_key>
DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com

=== Summary of Findings ===

Domain: example.com
[✓] SPF Record Found
[✓] DKIM Record Found
[✓] DMARC Record Found
```

### CSV Output (`results.csv`)
| Domain             | SPF                                      | DKIM                                | DMARC                                   | Warnings                                                                 |
|--------------------|------------------------------------------|-------------------------------------|-----------------------------------------|--------------------------------------------------------------------------|
| example.com        | v=spf1 include:_spf.google.com ~all     | Found (google): v=DKIM1; k=rsa; p=... | v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com |                                                                          |
| test.com           | v=spf1 +all                             | Not Found                          | Not Found                              | SPF record does not end with '~all' or '-all'. This may allow unauthorized senders. |

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add feature or fix"
   ```
4. Push your branch to GitHub:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request explaining your changes.

### Reporting Issues
If you encounter any bugs or have suggestions for improvements, please open an issue in the [Issues](https://github.com/anir0y/dns-scanner/issues) section.

## License

This project is licensed under the [Chaos & Code License.](LICENSE.MD)

