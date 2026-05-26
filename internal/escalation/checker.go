package escalation

import (
	"strings"

	"github.com/francescocitti/go-escalation-check/internal/iam"
)

type Finding struct {
	PrincipalARN  string       `json:"principal_arn"`
	PrincipalName string       `json:"principal_name"`
	PrincipalKind string       `json:"principal_kind"`
	Technique     Technique    `json:"technique"`
	MITRE         MITREMapping `json:"mitre"`
	Severity      string       `json:"severity"`
}

// permSet is the set of IAM actions allowed for a principal.
type permSet map[string]bool

func Check(snap *iam.AccountSnapshot) []Finding {
	policyIndex := buildPolicyIndex(snap)
	groupIndex := buildGroupIndex(snap)

	var findings []Finding

	for _, user := range snap.Users {
		perms := collectUserPerms(user, policyIndex, groupIndex)
		findings = append(findings, evaluate(user.ARN, user.Name, "user", perms)...)
	}

	for _, role := range snap.Roles {
		perms := collectRolePerms(role, policyIndex)
		findings = append(findings, evaluate(role.ARN, role.Name, "role", perms)...)
	}

	return findings
}

func evaluate(arn, name, kind string, perms permSet) []Finding {
	var findings []Finding
	for _, tech := range Techniques {
		if allGranted(perms, tech.Required) {
			findings = append(findings, Finding{
				PrincipalARN:  arn,
				PrincipalName: name,
				PrincipalKind: kind,
				Technique:     tech,
				MITRE:         LookupMITRE(tech.MitreKey),
				Severity:      tech.Severity,
			})
		}
	}
	return findings
}

func allGranted(perms permSet, actions []string) bool {
	for _, a := range actions {
		if !hasPermission(perms, a) {
			return false
		}
	}
	return true
}

func hasPermission(perms permSet, action string) bool {
	if perms["*"] {
		return true
	}
	if perms[action] {
		return true
	}
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 && perms[parts[0]+":*"] {
		return true
	}
	return false
}

func collectUserPerms(user iam.User, policyIndex map[string]iam.PolicyDocument, groupIndex map[string]*iam.Group) permSet {
	perms := make(permSet)

	for _, ref := range user.AttachedPolicies {
		if doc, ok := policyIndex[ref.ARN]; ok {
			extractAllowed(doc, perms)
		}
	}
	for _, ip := range user.InlinePolicies {
		extractAllowed(ip.Document, perms)
	}

	for _, groupName := range user.Groups {
		grp, ok := groupIndex[groupName]
		if !ok {
			continue
		}
		for _, ref := range grp.AttachedPolicies {
			if doc, ok := policyIndex[ref.ARN]; ok {
				extractAllowed(doc, perms)
			}
		}
		for _, ip := range grp.InlinePolicies {
			extractAllowed(ip.Document, perms)
		}
	}

	return perms
}

func collectRolePerms(role iam.Role, policyIndex map[string]iam.PolicyDocument) permSet {
	perms := make(permSet)

	for _, ref := range role.AttachedPolicies {
		if doc, ok := policyIndex[ref.ARN]; ok {
			extractAllowed(doc, perms)
		}
	}
	for _, ip := range role.InlinePolicies {
		extractAllowed(ip.Document, perms)
	}

	return perms
}

func extractAllowed(doc iam.PolicyDocument, perms permSet) {
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		for _, action := range stmt.Action {
			perms[action] = true
		}
	}
}

func buildPolicyIndex(snap *iam.AccountSnapshot) map[string]iam.PolicyDocument {
	idx := make(map[string]iam.PolicyDocument, len(snap.Policies))
	for _, p := range snap.Policies {
		idx[p.ARN] = p.Document
	}
	return idx
}

func buildGroupIndex(snap *iam.AccountSnapshot) map[string]*iam.Group {
	idx := make(map[string]*iam.Group, len(snap.Groups))
	for i := range snap.Groups {
		idx[snap.Groups[i].ARN] = &snap.Groups[i]
		idx[snap.Groups[i].Name] = &snap.Groups[i]
	}
	return idx
}
