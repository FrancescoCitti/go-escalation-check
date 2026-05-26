package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/francescocitti/go-escalation-check/internal/iam"
)

var (
	snapProfile string
	snapRegion  string
	snapOutput  string
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Capture live AWS IAM state to a JSON file for offline analysis",
	Long: `Connect to a live AWS account and dump all IAM entities to a portable JSON
snapshot file. The snapshot can be used with the scan command offline, shared
with a team, or committed to a repository for historical diffing.

Required IAM permissions:
  iam:GetAccountAuthorizationDetails

Example:
  go-escalation-check snapshot --profile prod --output prod_iam.json`,
	RunE: runSnapshot,
}

func init() {
	rootCmd.AddCommand(snapshotCmd)

	snapshotCmd.Flags().StringVar(&snapProfile, "profile", "", "AWS named profile")
	snapshotCmd.Flags().StringVar(&snapRegion, "region", "us-east-1", "AWS region")
	snapshotCmd.Flags().StringVar(&snapOutput, "output", "iam_snapshot.json", "output file path")
}

func runSnapshot(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(os.Stderr, "Connecting to AWS (profile=%q region=%q)\n", snapProfile, snapRegion)

	snap, err := iam.LoadLive(snapProfile, snapRegion)
	if err != nil {
		return fmt.Errorf("loading IAM data: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Loaded  %d users  %d roles  %d groups  %d managed policies\n",
		len(snap.Users), len(snap.Roles), len(snap.Groups), len(snap.Policies))

	if err := iam.SaveSnapshot(snap, snapOutput); err != nil {
		return fmt.Errorf("saving snapshot: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Snapshot written to %s\n", snapOutput)
	return nil
}
