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
  author: "narayanan"
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
        name: pantheon.io
        words:
          - "The gods are wise, but do not know of the site which you seek."

      - type: regex
        name: worksites
        regex:
          - "(?:Company Not Found|you&rsquo;re looking for doesn&rsquo;t exist)"

      - type: word
        name: aws-s3-bucket
        words:
          - "The specified bucket does not exist"

      - type: word
        name: github
        words:
          - "There isn't a GitHub Pages site here."
          - "For root URLs (like http://example.com/) you must provide an index.html file"

      - type: word
        name: heroku
        words:
          - "There's nothing here, yet."
          - "herokucdn.com/error-pages/no-such-app.html"
          - "<title>No such app</title>"

      - type: word
        name: bitbucket
        words:
          - "The page you have requested does not exist"
          - "Repository not found"

      - type: word
        name: smartling
        words:
          - "Domain is not configured"

      - type: word
        name: acquia
        words:
          - "If you are an Acquia Cloud customer and expect to see your site at this address"
          - "The site you are looking for could not be found."

      - type: word
        name: uservoice
        words:
          - "This UserVoice subdomain is currently available!"

      - type: word
        name: ghost
        words:
          - "The thing you were looking for is no longer here"
          - "The thing you were looking for is no longer here, or never was"

      - type: word
        name: tilda
        words:
          - "Domain has been assigned"

      - type: word
        name: wordpress
        words:
          - "Do you want to register"

      - type: word
        name: teamwork
        words:
          - "Oops - We didn't find your site."

      - type: word
        name: helpjuice
        words:
          - "We could not find what you're looking for."

      - type: word
        name: helpscout
        words:
          - "No settings were found for this company:"

      - type: word
        name: cargo
        words:
          - "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel."

      - type: word
        name: feedpress
        words:
          - "The feed has not been found."

      - type: word
        name: surge
        words:
          - "project not found"

      - type: word
        name: surveygizmo
        words:
          - "data-html-name"

      - type: word
        name: mashery
        words:
          - "Unrecognized domain <strong>"

      - type: word
        name: intercom
        words:
          - "This page is reserved for artistic dogs."
          - "<h1 class='headline'>Uh oh. That page doesn’t exist.</h1>"

      - type: word
        name: webflow
        words:
          - "<p class='description'>The page you are looking for doesn't exist or has been moved.</p>"

      - type: word
        name: thinkific
        words:
          - "You may have mistyped the address or the page may have moved."

      - type: word
        name: tave
        words:
          - "<h1>Error 404: Page Not Found</h1>"

      - type: word
        name: wishpond
        words:
          - "https://www.wishpond.com/404?campaign=true"

      - type: word
        name: aftership
        words:
          - "Oops.</h2><p class='text-muted text-tight'>The page you're looking for doesn't exist."

      - type: word
        name: aha
        words:
          - "There is no portal here ... sending you back to Aha!"

      - type: word
        name: brightcove
        words:
          - "<p class='bc-gallery-error-code'>Error Code: 404</p>"

      - type: word
        name: bigcartel
        words:
          - "<h1>Oops! We couldn&#8217;t find that page.</h1>"

      - type: word
        name: activecompaign
        words:
          - "alt='LIGHTTPD - fly light.'"

      - type: word
        name: compaignmonitor
        words:
          - "Double check the URL or <a href='mailto:help@createsend.com'"

      - type: word
        name: acquia
        words:
          - "The site you are looking for could not be found."

      - type: word
        name: proposify
        words:
          - "If you need immediate assistance, please contact <a href='mailto:support@proposify.biz'"

      - type: word
        name: simplebooklet
        words:
          - "We can't find this <a href='https://simplebooklet.com'"

      - type: word
        name: getresponse
        words:
          - "With GetResponse Landing Pages, lead generation has never been easier"

      - type: word
        name: vend
        words:
          - "Looks like you've traveled too far into cyberspace."

      - type: word
        name: jetbrains
        words:
          - "is not a registered InCloud YouTrack."

      - type: word
        name: readme
        words:
          - "Project doesnt exist... yet!"

      - type: word
        name: smugmug
        words:
          - '{"text":"Page Not Found"}'

      - type: word
        name: airee
        words:
          - "Ошибка 402. Сервис Айри.рф не оплачен"

      - type: word
        name: kinsta
        words:
          - "No Site For Domain"

      - type: word
        name: launchrock
        words:
          - "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."

      - type: word
        name: Strikingly
        words:
          - "But if you're looking to build your own website"
          - "you've come to the right place."

      - type: word
        name: HatenaBlog
        words:
          - "404 Blog is not found"
          - "Sorry, we can't find the page you're looking for."

      - type: word
        name: wufoo
        words:
          - "Profile not found"
          - "Hmmm....something is not right."

      - type: word
        name: hubspot
        words:
          - "Domain not found"
          - "does not exist in our system"

      - type: word
        name: jazzhr
        words:
          - "This account no longer active"

      - type: word
        name: smartjob
        words:
          - "Job Board Is Unavailable"
          - "This job board website is either expired"
          - "This job board website is either expired or its domain name is invalid."

      - type: regex
        name: Uptimerobot
        regex:
          - "^page not found$"

      - type: word
        name: agile
        words:
          - "Sorry, this page is no longer available."

      - type: word
        name: pingdom
        words:
          - "Public Report Not Activated"
          - "This public report page has not been activated by the user"

      - type: word
        name: zendesk
        words:
          - "this help center no longer exists"`
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
