//go:build debug

// Package verifier contains RCE verification logic.
//
// This file contains DEBUG-ONLY RCE proof indicators used during local
// development and testing against personal labs. These indicators are
// NEVER included in production builds because they are environment-specific
// and would cause false negatives on real targets.
//
// To enable: `go build -tags debug`
// To disable (default production build): `go build`
package verifier

var debugIndicators = []string{
	"haakimsec", // Personal username
	"kali",      // Kali Linux default user
	"parrot",    // Parrot OS default user
	"ubuntu",    // Default cloud user (Amazon EC2, etc.)
	"ec2-user",  // AWS EC2 default
	"azureuser", // Azure default
}
