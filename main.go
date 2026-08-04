package main

import (
	"fmt"
	"os"

	"github.com/HaakimSec/GoUpload/internal/app"
	"github.com/HaakimSec/GoUpload/internal/config"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  Error: %s\n\n", err)
		os.Exit(1)
	}

	application := app.New(cfg)
	if err := application.Run(); err != nil {
		os.Exit(1)
	}
}
