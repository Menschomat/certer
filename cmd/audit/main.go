package main

import (
	"os"
)

func main() {
	os.Exit(runAudit(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}
