package fingerprint

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TechStack represents the detected technology stack of the target
type TechStack struct {
	Server      string // Apache, Nginx, IIS, Express, Tomcat, etc.
	Language    string // PHP, ASP.NET, Java, Node.js, Python, Ruby
	Framework   string // Laravel, Express, Django, Rails, Spring
	OS          string // Linux, Windows
	Confidence  int    // 0-100% confidence level
}

// Fingerprint performs passive reconnaissance on the target URL
// to determine the technology stack before sending payloads
func Fingerprint(targetURL string, headers map[string]string) (*TechStack, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create fingerprint request: %w", err)
	}

	// Set User-Agent
	req.Header.Set("User-Agent", "GoUpload-Fingerprint/1.0")
	
	// Add custom headers if provided
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fingerprint request failed: %w", err)
	}
	defer resp.Body.Close()

	ts := &TechStack{}
	evidence := []string{}

	// 1. Check Server header
	server := resp.Header.Get("Server")
	if server != "" {
		ts.Server = parseServer(server)
		evidence = append(evidence, fmt.Sprintf("Server: %s", server))
	}

	// 2. Check X-Powered-By (most reliable indicator)
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		lang := parsePoweredBy(poweredBy)
		if lang != "" {
			ts.Language = lang
			ts.Confidence += 60 // Very high confidence
			evidence = append(evidence, fmt.Sprintf("X-Powered-By: %s", poweredBy))
		}
	}

	// 3. Check Set-Cookie headers for session IDs
	cookies := resp.Header["Set-Cookie"]
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		switch {
		case strings.Contains(cookieLower, "phpsessid"):
			ts.Language = "PHP"
			ts.Confidence += 40
			evidence = append(evidence, "Cookie: PHPSESSID (PHP)")
		case strings.Contains(cookieLower, "asp.net_sessionid"):
			ts.Language = "ASP.NET"
			ts.Confidence += 40
			evidence = append(evidence, "Cookie: ASP.NET_SessionId")
		case strings.Contains(cookieLower, "jsessionid"):
			ts.Language = "Java"
			ts.Confidence += 40
			evidence = append(evidence, "Cookie: JSESSIONID (Java)")
		case strings.Contains(cookieLower, "express.sid"):
			ts.Language = "Node.js"
			ts.Confidence += 40
			evidence = append(evidence, "Cookie: express.sid (Node.js)")
		}
	}

	// 4. Check URL extension
	urlLower := strings.ToLower(targetURL)
	switch {
	case strings.Contains(urlLower, ".php"):
		ts.Language = "PHP"
		ts.Confidence += 30
		evidence = append(evidence, "URL extension: .php")
	case strings.Contains(urlLower, ".asp") || strings.Contains(urlLower, ".aspx"):
		ts.Language = "ASP.NET"
		ts.Confidence += 30
		evidence = append(evidence, "URL extension: .asp/.aspx")
	case strings.Contains(urlLower, ".jsp"):
		ts.Language = "Java"
		ts.Confidence += 30
		evidence = append(evidence, "URL extension: .jsp")
	}

	// 5. Check Content-Type for framework hints
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		// Check for framework-specific patterns in headers
		if resp.Header.Get("X-Drupal-Cache") != "" {
			ts.Framework = "Drupal"
			ts.Language = "PHP"
			ts.Confidence += 20
		}
		if resp.Header.Get("X-Generator") != "" {
			gen := resp.Header.Get("X-Generator")
			ts.Framework = gen
			if strings.Contains(strings.ToLower(gen), "wordpress") {
				ts.Language = "PHP"
				ts.Confidence += 30
			}
		}
	}

	// 6. Infer language from server if not yet determined
	if ts.Language == "" && ts.Server != "" {
		switch ts.Server {
		case "Apache":
			ts.Language = "PHP" // Most common on Apache
			ts.Confidence += 20
		case "IIS":
			ts.Language = "ASP.NET" // Most common on IIS
			ts.Confidence += 20
		case "Tomcat":
			ts.Language = "Java"
			ts.Confidence += 20
		}
	}

	// Cap confidence at 100
	if ts.Confidence > 100 {
		ts.Confidence = 100
	}

	// Print fingerprint results
	printFingerprintResults(ts, evidence)

	return ts, nil
}

// parseServer extracts the server type from the Server header
func parseServer(server string) string {
	serverLower := strings.ToLower(server)
	switch {
	case strings.Contains(serverLower, "apache"):
		return "Apache"
	case strings.Contains(serverLower, "nginx"):
		return "Nginx"
	case strings.Contains(serverLower, "iis"):
		return "IIS"
	case strings.Contains(serverLower, "tomcat"):
		return "Tomcat"
	case strings.Contains(serverLower, "express"):
		return "Express"
	case strings.Contains(serverLower, "gunicorn"):
		return "Gunicorn"
	case strings.Contains(serverLower, "uwsgi"):
		return "uWSGI"
	default:
		return server
	}
}

// parsePoweredBy extracts the language from X-Powered-By header
func parsePoweredBy(poweredBy string) string {
	lower := strings.ToLower(poweredBy)
	switch {
	case strings.Contains(lower, "php"):
		return "PHP"
	case strings.Contains(lower, "asp.net"):
		return "ASP.NET"
	case strings.Contains(lower, "express"):
		return "Node.js"
	case strings.Contains(lower, "node"):
		return "Node.js"
	default:
		return poweredBy
	}
}

// printFingerprintResults displays the fingerprint findings
func printFingerprintResults(ts *TechStack, evidence []string) {
	fmt.Println()
	fmt.Println("  ┌─ TARGET FINGERPRINT ─────────────────────────────────────────────┐")
	
	if ts.Server != "" {
		fmt.Printf("  │  🖥  Server      : %-50s │\n", ts.Server)
	}
	if ts.Language != "" {
		fmt.Printf("  │  💻 Language    : %-50s │\n", ts.Language)
	}
	if ts.Framework != "" {
		fmt.Printf("  │  🏗  Framework   : %-50s │\n", ts.Framework)
	}
	if ts.Confidence > 0 {
		fmt.Printf("  │  📊 Confidence  : %d%% %-47s │\n", ts.Confidence, "")
	}
	
	if len(evidence) > 0 {
		fmt.Println("  │                                                                  │")
		fmt.Println("  │  Evidence:                                                       │")
		for _, ev := range evidence {
			if len(ev) > 62 {
				ev = ev[:59] + "..."
			}
			fmt.Printf("  │    • %-60s │\n", ev)
		}
	}
	
	fmt.Println("  └──────────────────────────────────────────────────────────────────┘")
	fmt.Println()
}
