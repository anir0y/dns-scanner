package main

import (
    "encoding/csv"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "bufio"
)

// Common DKIM selectors
var commonDKIMSelectors = []string{
    "default", "google", "mail", "selector1", "selector2", "dkim", "smtp",
    "k1", "k2", "mx", "email", "eml", "outbound", "inbound", "relay",
    "s1", "s2", "key1", "key2", "domainkey", "dkim1", "dkim2",
    "sendgrid", "mandrill", "postmark", "amazonses", "zoho", "office365",
}

// RecordCheckResult holds the result of a DNS record check
type RecordCheckResult struct {
    Domain   string
    SPF      string
    DKIM     string
    DMARC    string
    Warnings []string
}

func checkSPF(domain string) (string, []string) {
    txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        return "Not Found", nil
    }

    for _, txt := range txtRecords {
        if strings.HasPrefix(txt, "v=spf1") {
            warnings := []string{}
            if !strings.Contains(txt, "~all") && !strings.Contains(txt, "-all") {
                warnings = append(warnings, "SPF record does not end with '~all' or '-all'. This may allow unauthorized senders.")
            }
            return txt, warnings
        }
    }
    return "Not Found", nil
}

func checkDKIM(domain string) (string, []string) {
    for _, selector := range commonDKIMSelectors {
        dkimQuery := fmt.Sprintf("%s._domainkey.%s", selector, domain)
        txtRecords, err := net.LookupTXT(dkimQuery)
        if err == nil {
            for _, txt := range txtRecords {
                if strings.HasPrefix(txt, "v=DKIM1") {
                    return fmt.Sprintf("Found (%s): %s", selector, txt), nil
                }
            }
        }
    }
    return "Not Found", nil
}

func checkDMARC(domain string) (string, []string) {
    dmarcQuery := fmt.Sprintf("_dmarc.%s", domain)
    txtRecords, err := net.LookupTXT(dmarcQuery)
    if err != nil {
        return "Not Found", nil
    }

    for _, txt := range txtRecords {
        if strings.HasPrefix(txt, "v=DMARC1") {
            warnings := []string{}
            if strings.Contains(txt, "p=none") {
                warnings = append(warnings, "DMARC policy is set to 'none'. This means no action will be taken on failed emails.")
            } else if !strings.Contains(txt, "p=quarantine") && !strings.Contains(txt, "p=reject") {
                warnings = append(warnings, "DMARC policy is not set to 'quarantine' or 'reject'. Consider strengthening it.")
            }
            return txt, warnings
        }
    }
    return "Not Found", nil
}

func scanDomain(domain string) RecordCheckResult {
    fmt.Printf("Scanning domain: %s\n", domain)

    spf, spfWarnings := checkSPF(domain)
    dkim, dkimWarnings := checkDKIM(domain)
    dmarc, dmarcWarnings := checkDMARC(domain)

    warnings := append(spfWarnings, dkimWarnings...)
    warnings = append(warnings, dmarcWarnings...)

    result := RecordCheckResult{
        Domain:   domain,
        SPF:      spf,
        DKIM:     dkim,
        DMARC:    dmarc,
        Warnings: warnings,
    }

    fmt.Printf("SPF: %s\nDKIM: %s\nDMARC: %s\n\n", spf, dkim, dmarc)
    return result
}

func scanDomainsFromFile(filePath string) []RecordCheckResult {
    file, err := os.Open(filePath)
    if err != nil {
        log.Fatalf("Failed to open file: %v", err)
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domain := strings.TrimSpace(scanner.Text())
        if domain != "" {
            domains = append(domains, domain)
        }
    }

    if err := scanner.Err(); err != nil {
        log.Fatalf("Error reading file: %v", err)
    }

    var results []RecordCheckResult
    for _, domain := range domains {
        results = append(results, scanDomain(domain))
    }
    return results
}

func saveResultsToCSV(results []RecordCheckResult, filePath string) {
    file, err := os.Create(filePath)
    if err != nil {
        log.Fatalf("Failed to create CSV file: %v", err)
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Write header
    writer.Write([]string{"Domain", "SPF", "DKIM", "DMARC", "Warnings"})

    // Write results
    for _, result := range results {
        warnings := strings.Join(result.Warnings, "; ")
        writer.Write([]string{result.Domain, result.SPF, result.DKIM, result.DMARC, warnings})
    }
}

func printSummary(results []RecordCheckResult) {
    fmt.Println("\n=== Summary of Findings ===")
    for _, result := range results {
        fmt.Printf("\nDomain: %s\n", result.Domain)

        // SPF Summary
        if result.SPF != "Not Found" {
            fmt.Println("[✓] SPF Record Found")
            if len(result.Warnings) > 0 {
                fmt.Println("    Warnings:")
                for _, warning := range result.Warnings {
                    if strings.Contains(warning, "SPF") {
                        fmt.Printf("    - %s\n", warning)
                    }
                }
            }
        } else {
            fmt.Println("[✗] SPF Record Missing")
            fmt.Println("    Suggestion: Add an SPF record to your DNS settings. Example: 'v=spf1 include:_spf.google.com ~all'")
        }

        // DKIM Summary
        if result.DKIM != "Not Found" {
            fmt.Println("[✓] DKIM Record Found")
        } else {
            fmt.Println("[✗] DKIM Record Missing")
            fmt.Println("    Suggestion: Add a DKIM record to your DNS settings. Example: 'v=DKIM1; k=rsa; p=<public_key>'")
        }

        // DMARC Summary
        if result.DMARC != "Not Found" {
            fmt.Println("[✓] DMARC Record Found")
            if len(result.Warnings) > 0 {
                fmt.Println("    Warnings:")
                for _, warning := range result.Warnings {
                    if strings.Contains(warning, "DMARC") {
                        fmt.Printf("    - %s\n", warning)
                    }
                }
            }
        } else {
            fmt.Println("[✗] DMARC Record Missing")
            fmt.Println("    Suggestion: Add a DMARC record to your DNS settings. Example: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com'")
        }
    }
}

func printHelp() {
    fmt.Println("Usage:")
    fmt.Println("  dns-scanner [flags]")
    fmt.Println("\nFlags:")
    fmt.Println("  -d string")
    fmt.Println("        Scan a single domain (e.g., example.com)")
    fmt.Println("  -f string")
    fmt.Println("        Scan domains from a file (one domain per line)")
    fmt.Println("  -o string")
    fmt.Println("        Save results to a CSV file")
    fmt.Println("\nExample Usage:")
    fmt.Println("  dns-scanner -d example.com")
    fmt.Println("  dns-scanner -f domains.txt")
    fmt.Println("  dns-scanner -f domains.txt -o results.csv")
}

func main() {
    // Define flags
    domainFlag := flag.String("d", "", "Scan a single domain")
    fileFlag := flag.String("f", "", "Scan domains from a file")
    outputFlag := flag.String("o", "", "Save results to a CSV file")
    flag.Parse()

    // Check if any flags were provided
    if *domainFlag == "" && *fileFlag == "" && *outputFlag == "" {
        printHelp()
        return
    }

    var results []RecordCheckResult

    // Scan a single domain
    if *domainFlag != "" {
        results = append(results, scanDomain(*domainFlag))
    }

    // Scan domains from a file
    if *fileFlag != "" {
        results = scanDomainsFromFile(*fileFlag)
    }

    // Print summary
    printSummary(results)

    // Save results to CSV if output flag is provided
    if *outputFlag != "" {
        saveResultsToCSV(results, *outputFlag)
        fmt.Printf("Results saved to %s\n", *outputFlag)
    }
}