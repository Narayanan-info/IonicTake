package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	nucleiInstallCmd = "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
	customTemplate   = `id: enhanced-detect-all-takeovers
info:
  name: Enhanced Subdomain Takeover Finder
  author: "melbadry9 & pxmme1337"
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 404
          - 403
      - type: word
        name: github
        words:
          - "There isn't a GitHub Pages site here."
          - "For root URLs (like http://example.com/) you must provide an index.html file"
      - type: word
        name: aws-s3-bucket
        words:
          - "The specified bucket does not exist"`
)

var banner = `
███████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  █████╗ ██╗███╗   ██╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║
███████╗██║   ██║██████╔╝███████╗██║  ██║██████╔╝███████║██║██╔██╗ ██║
╚════██║██║   ██║██╔══██╗╚════██║██║  ██║██╔══██╗██╔══██║██║██║╚██╗██║
███████║╚██████╔╝██████╔╝███████║██████╔╝██║  ██║██║  ██║██║██║ ╚████║
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
                          Subdomain Takeover Detector
`

func main() {
	// Display the ASCII banner
	fmt.Println(banner)

	// Parse command-line arguments
	subdomainFile := flag.String("f", "", "Path to the subdomain list file")
	flag.Parse()

	if *subdomainFile == "" {
		log.Fatal("[-] Please provide a subdomain list file using the -f flag.")
	}

	// Step 1: Install Nuclei
	fmt.Println("[*] Installing Nuclei...")
	installNuclei()

	// Step 2: Save the custom template to a file
	templatePath := filepath.Join(os.TempDir(), "subdomain-takeover.yaml")
	fmt.Printf("[*] Saving custom template to: %s\n", templatePath)
	if err := os.WriteFile(templatePath, []byte(customTemplate), 0644); err != nil {
		log.Fatalf("[-] Failed to save template: %v\n", err)
	}

	// Step 3: Run Nuclei with the custom template
	fmt.Println("[*] Running Nuclei to detect subdomain takeovers...")
	cmd := exec.Command("nuclei", "-t", templatePath, "-l", *subdomainFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Error running Nuclei: %v\nOutput:\n%s", err, string(output))
	}

	// Step 4: Display results
	fmt.Println("[+] Nuclei Output:")
	fmt.Println(string(output))
}

func installNuclei() {
	cmd := exec.Command("sh", "-c", nucleiInstallCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Failed to install Nuclei: %v\nOutput:\n%s", err, string(output))
	}
	fmt.Println("[+] Nuclei installed successfully.")
}
