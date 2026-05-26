package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/francescocitti/go-escalation-check/internal/escalation"
	"github.com/francescocitti/go-escalation-check/internal/iam"
	"github.com/francescocitti/go-escalation-check/internal/jit"
	"github.com/francescocitti/go-escalation-check/internal/terraform"
)

var (
	snapshotFile string
	awsProfile   string
	awsRegion    string
	outputFormat string
	genJIT       bool
	genTerraform bool
	outDir       string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AWS IAM configuration for privilege escalation paths",
	Long: `Scan reads your AWS IAM configuration (from a live account or a JSON snapshot),
builds a directed permission graph, and identifies all privilege escalation paths
to administrator-level access.

Each finding includes the affected principal, escalation technique, required IAM
actions, and the corresponding MITRE ATT&CK technique ID.

Examples:
  # Scan from a saved snapshot (no AWS credentials needed)
  go-escalation-check scan --snapshot testdata/sample_snapshot.json

  # Scan a live account using the default AWS profile
  go-escalation-check scan

  # Scan and export JIT policies + Terraform HCL
  go-escalation-check scan --snapshot testdata/sample_snapshot.json --jit --terraform --outdir ./remediation`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(&snapshotFile, "snapshot", "", "path to IAM snapshot JSON file (skips live API)")
	scanCmd.Flags().StringVar(&awsProfile, "profile", "", "AWS named profile")
	scanCmd.Flags().StringVar(&awsRegion, "region", "us-east-1", "AWS region")
	scanCmd.Flags().StringVar(&outputFormat, "format", "table", "output format: table, json")
	scanCmd.Flags().BoolVar(&genJIT, "jit", false, "write JIT restriction policies to --outdir")
	scanCmd.Flags().BoolVar(&genTerraform, "terraform", false, "write Terraform HCL remediation to --outdir")
	scanCmd.Flags().StringVar(&outDir, "outdir", ".", "output directory for generated files")
}

func runScan(cmd *cobra.Command, args []string) error {
	var (
		snap *iam.AccountSnapshot
		err  error
	)

	if snapshotFile != "" {
		fmt.Fprintf(os.Stderr, "Loading IAM snapshot: %s\n", snapshotFile)
		snap, err = iam.LoadSnapshot(snapshotFile)
	} else {
		fmt.Fprintf(os.Stderr, "Connecting to AWS (profile=%q region=%q)\n", awsProfile, awsRegion)
		snap, err = iam.LoadLive(awsProfile, awsRegion)
	}
	if err != nil {
		return fmt.Errorf("loading IAM data: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Loaded  %d users  %d roles  %d groups  %d managed policies\n\n",
		len(snap.Users), len(snap.Roles), len(snap.Groups), len(snap.Policies))

	findings := escalation.Check(snap)

	if len(findings) == 0 {
		fmt.Println("No privilege escalation paths found.")
		return nil
	}

	switch outputFormat {
	case "table":
		printTable(findings)
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (use table or json)", outputFormat)
	}

	if !genJIT && !genTerraform {
		return nil
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if genJIT {
		policies := jit.Generate(findings)
		outPath := filepath.Join(outDir, "jit_policies.json")
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating JIT policy file: %w", err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(policies); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nJIT policies  -> %s\n", outPath)
	}

	if genTerraform {
		hcl := terraform.Export(findings)
		outPath := filepath.Join(outDir, "iam_remediation.tf")
		if err := os.WriteFile(outPath, []byte(hcl), 0o644); err != nil {
			return fmt.Errorf("writing Terraform file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Terraform HCL -> %s\n", outPath)
	}

	return nil
}

func printTable(findings []escalation.Finding) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Principal", "Kind", "Technique", "MITRE", "Severity"})
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(true)
	table.SetColWidth(42)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
	)

	for _, f := range findings {
		sevColor := severityColor(f.Severity)
		table.Rich(
			[]string{
				f.PrincipalName,
				f.PrincipalKind,
				f.Technique.Name,
				f.MITRE.SubtechniqueID,
				strings.ToUpper(f.Severity),
			},
			[]tablewriter.Colors{
				{tablewriter.Bold},
				{tablewriter.FgCyanColor},
				{},
				{tablewriter.FgBlueColor},
				{sevColor, tablewriter.Bold},
			},
		)
	}

	table.Render()
	fmt.Printf("\n%d finding(s) across %d principal(s)\n", len(findings), uniquePrincipals(findings))
}

func severityColor(sev string) int {
	switch sev {
	case "critical":
		return tablewriter.FgRedColor
	case "high":
		return tablewriter.FgYellowColor
	case "medium":
		return tablewriter.FgCyanColor
	default:
		return tablewriter.FgWhiteColor
	}
}

func uniquePrincipals(findings []escalation.Finding) int {
	seen := make(map[string]bool)
	for _, f := range findings {
		seen[f.PrincipalARN] = true
	}
	return len(seen)
}
