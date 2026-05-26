package jit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/francescocitti/go-escalation-check/internal/escalation"
)

type Policy struct {
	PrincipalARN string   `json:"principal_arn"`
	PolicyName   string   `json:"policy_name"`
	Document     Document `json:"document"`
	Rationale    string   `json:"rationale"`
	ExpiresAt    string   `json:"expires_at"`
}

type Document struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid       string            `json:"Sid,omitempty"`
	Effect    string            `json:"Effect"`
	Action    []string          `json:"Action"`
	Resource  string            `json:"Resource"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

func Generate(findings []escalation.Finding) []Policy {
	byPrincipal := make(map[string][]escalation.Finding)
	for _, f := range findings {
		byPrincipal[f.PrincipalARN] = append(byPrincipal[f.PrincipalARN], f)
	}

	var policies []Policy
	for arn, pf := range byPrincipal {
		policies = append(policies, generateForPrincipal(arn, pf))
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].PrincipalARN < policies[j].PrincipalARN
	})

	return policies
}

func generateForPrincipal(arn string, findings []escalation.Finding) Policy {
	dangerous := make(map[string]bool)
	var techniqueNames []string

	for _, f := range findings {
		for _, action := range f.Technique.Required {
			dangerous[action] = true
		}
		techniqueNames = append(techniqueNames, f.Technique.Name)
	}

	denyActions := sortedKeys(dangerous)
	expiry := time.Now().UTC().Add(8 * time.Hour).Format(time.RFC3339)
	shortName := arnShortName(arn)
	policyName := "jit_restrict_" + strings.ToLower(strings.ReplaceAll(shortName, ".", "_"))

	return Policy{
		PrincipalARN: arn,
		PolicyName:   policyName,
		Document: Document{
			Version: "2012-10-17",
			Statement: []Statement{
				{
					Sid:      "DenyEscalationPaths",
					Effect:   "Deny",
					Action:   denyActions,
					Resource: "*",
					Condition: map[string]interface{}{
						"Bool": map[string]string{
							"aws:MultiFactorAuthPresent": "false",
						},
						"DateGreaterThan": map[string]string{
							"aws:CurrentTime": expiry,
						},
					},
				},
			},
		},
		Rationale: fmt.Sprintf("Blocks %d escalation technique(s): %s",
			len(findings), strings.Join(techniqueNames, ", ")),
		ExpiresAt: expiry,
	}
}

func (p Policy) JSON() (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func arnShortName(arn string) string {
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
