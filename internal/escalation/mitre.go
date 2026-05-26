package escalation

type MITREMapping struct {
	TechniqueID    string `json:"technique_id"`
	TechniqueName  string `json:"technique_name"`
	SubtechniqueID string `json:"subtechnique_id"`
	URL            string `json:"url"`
}

var mitreMap = map[string]MITREMapping{
	"assume_role": {
		TechniqueID:    "T1078",
		TechniqueName:  "Valid Accounts",
		SubtechniqueID: "T1078.004",
		URL:            "https://attack.mitre.org/techniques/T1078/004/",
	},
	"create_policy_version": {
		TechniqueID:    "T1484",
		TechniqueName:  "Domain Policy Modification",
		SubtechniqueID: "T1484.001",
		URL:            "https://attack.mitre.org/techniques/T1484/",
	},
	"attach_policy": {
		TechniqueID:    "T1098",
		TechniqueName:  "Account Manipulation",
		SubtechniqueID: "T1098.003",
		URL:            "https://attack.mitre.org/techniques/T1098/003/",
	},
	"put_policy": {
		TechniqueID:    "T1098",
		TechniqueName:  "Account Manipulation",
		SubtechniqueID: "T1098.003",
		URL:            "https://attack.mitre.org/techniques/T1098/003/",
	},
	"pass_role": {
		TechniqueID:    "T1548",
		TechniqueName:  "Abuse Elevation Control Mechanism",
		SubtechniqueID: "T1548",
		URL:            "https://attack.mitre.org/techniques/T1548/",
	},
	"create_role": {
		TechniqueID:    "T1136",
		TechniqueName:  "Create Account",
		SubtechniqueID: "T1136.003",
		URL:            "https://attack.mitre.org/techniques/T1136/003/",
	},
	"add_to_group": {
		TechniqueID:    "T1098",
		TechniqueName:  "Account Manipulation",
		SubtechniqueID: "T1098",
		URL:            "https://attack.mitre.org/techniques/T1098/",
	},
	"create_access_key": {
		TechniqueID:    "T1098",
		TechniqueName:  "Account Manipulation",
		SubtechniqueID: "T1098.001",
		URL:            "https://attack.mitre.org/techniques/T1098/001/",
	},
	"update_login": {
		TechniqueID:    "T1098",
		TechniqueName:  "Account Manipulation",
		SubtechniqueID: "T1098",
		URL:            "https://attack.mitre.org/techniques/T1098/",
	},
}

func LookupMITRE(key string) MITREMapping {
	if m, ok := mitreMap[key]; ok {
		return m
	}
	return MITREMapping{
		TechniqueID:   "T1078",
		TechniqueName: "Valid Accounts",
		URL:           "https://attack.mitre.org/techniques/T1078/",
	}
}
