package main

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
	// Load Trivy CLI to force imports.
	app := commands.NewApp("")
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
