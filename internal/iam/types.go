package iam

import "encoding/json"

type AccountSnapshot struct {
	AccountID string          `json:"account_id"`
	Users     []User          `json:"users"`
	Roles     []Role          `json:"roles"`
	Groups    []Group         `json:"groups"`
	Policies  []ManagedPolicy `json:"policies"`
}

type User struct {
	ARN              string          `json:"arn"`
	Name             string          `json:"name"`
	UserID           string          `json:"user_id"`
	Groups           []string        `json:"groups"`
	AttachedPolicies []PolicyRef     `json:"attached_policies"`
	InlinePolicies   []InlinePolicy  `json:"inline_policies"`
}

type Role struct {
	ARN              string          `json:"arn"`
	Name             string          `json:"name"`
	RoleID           string          `json:"role_id"`
	TrustDocument    PolicyDocument  `json:"trust_document"`
	AttachedPolicies []PolicyRef     `json:"attached_policies"`
	InlinePolicies   []InlinePolicy  `json:"inline_policies"`
}

type Group struct {
	ARN              string          `json:"arn"`
	Name             string          `json:"name"`
	GroupID          string          `json:"group_id"`
	Members          []string        `json:"members"`
	AttachedPolicies []PolicyRef     `json:"attached_policies"`
	InlinePolicies   []InlinePolicy  `json:"inline_policies"`
}

type ManagedPolicy struct {
	ARN      string         `json:"arn"`
	Name     string         `json:"name"`
	Document PolicyDocument `json:"document"`
}

type PolicyRef struct {
	ARN  string `json:"arn"`
	Name string `json:"name"`
}

type InlinePolicy struct {
	Name     string         `json:"name"`
	Document PolicyDocument `json:"document"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid       string                 `json:"Sid,omitempty"`
	Effect    string                 `json:"Effect"`
	Action    StringOrSlice          `json:"Action,omitempty"`
	NotAction StringOrSlice          `json:"NotAction,omitempty"`
	Resource  StringOrSlice          `json:"Resource,omitempty"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
	Principal *PrincipalSpec         `json:"Principal,omitempty"`
}

type PrincipalSpec struct {
	AWS       StringOrSlice `json:"AWS,omitempty"`
	Service   StringOrSlice `json:"Service,omitempty"`
	Federated StringOrSlice `json:"Federated,omitempty"`
}

// StringOrSlice handles IAM policy fields that can be either a string or []string.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = StringOrSlice{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*s = StringOrSlice(multi)
	return nil
}

func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}
