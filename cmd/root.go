package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "go-escalation-check",
	Short: "AWS IAM privilege escalation path analyzer",
	Long: `go-escalation-check builds a directed permission graph from your AWS IAM
configuration and finds all privilege escalation paths to admin-level access.

Each finding maps to a MITRE ATT&CK technique and can be exported as a
minimal JIT restriction policy or Terraform HCL for immediate remediation.

Source account data from a live AWS call or a portable JSON snapshot.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
