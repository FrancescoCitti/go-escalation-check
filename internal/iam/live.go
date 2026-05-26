package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func LoadLive(profile, region string) (*AccountSnapshot, error) {
	ctx := context.Background()

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := awsiam.NewFromConfig(cfg)
	snap := &AccountSnapshot{}

	paginator := awsiam.NewGetAccountAuthorizationDetailsPaginator(client,
		&awsiam.GetAccountAuthorizationDetailsInput{
			Filter: []types.EntityType{
				types.EntityTypeUser,
				types.EntityTypeRole,
				types.EntityTypeGroup,
				types.EntityTypeLocalManagedPolicy,
				types.EntityTypeAWSManagedPolicy,
			},
		},
	)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching account authorization details: %w", err)
		}

		for _, u := range page.UserDetailList {
			snap.Users = append(snap.Users, convertUser(u))
		}
		for _, r := range page.RoleDetailList {
			snap.Roles = append(snap.Roles, convertRole(r))
		}
		for _, g := range page.GroupDetailList {
			snap.Groups = append(snap.Groups, convertGroup(g))
		}
		for _, p := range page.Policies {
			mp, err := convertManagedPolicy(p)
			if err != nil {
				continue
			}
			snap.Policies = append(snap.Policies, mp)
		}
	}

	return snap, nil
}

func convertUser(u types.UserDetail) User {
	user := User{
		ARN:    aws.ToString(u.Arn),
		Name:   aws.ToString(u.UserName),
		UserID: aws.ToString(u.UserId),
	}
	user.Groups = append(user.Groups, u.GroupList...)
	for _, p := range u.AttachedManagedPolicies {
		user.AttachedPolicies = append(user.AttachedPolicies, PolicyRef{
			ARN:  aws.ToString(p.PolicyArn),
			Name: aws.ToString(p.PolicyName),
		})
	}
	for _, ip := range u.UserPolicyList {
		doc, err := parseURLEncodedPolicy(aws.ToString(ip.PolicyDocument))
		if err != nil {
			continue
		}
		user.InlinePolicies = append(user.InlinePolicies, InlinePolicy{
			Name:     aws.ToString(ip.PolicyName),
			Document: doc,
		})
	}
	return user
}

func convertRole(r types.RoleDetail) Role {
	role := Role{
		ARN:    aws.ToString(r.Arn),
		Name:   aws.ToString(r.RoleName),
		RoleID: aws.ToString(r.RoleId),
	}
	if r.AssumeRolePolicyDocument != nil {
		doc, err := parseURLEncodedPolicy(aws.ToString(r.AssumeRolePolicyDocument))
		if err == nil {
			role.TrustDocument = doc
		}
	}
	for _, p := range r.AttachedManagedPolicies {
		role.AttachedPolicies = append(role.AttachedPolicies, PolicyRef{
			ARN:  aws.ToString(p.PolicyArn),
			Name: aws.ToString(p.PolicyName),
		})
	}
	for _, ip := range r.RolePolicyList {
		doc, err := parseURLEncodedPolicy(aws.ToString(ip.PolicyDocument))
		if err != nil {
			continue
		}
		role.InlinePolicies = append(role.InlinePolicies, InlinePolicy{
			Name:     aws.ToString(ip.PolicyName),
			Document: doc,
		})
	}
	return role
}

func convertGroup(g types.GroupDetail) Group {
	grp := Group{
		ARN:     aws.ToString(g.Arn),
		Name:    aws.ToString(g.GroupName),
		GroupID: aws.ToString(g.GroupId),
	}
	for _, p := range g.AttachedManagedPolicies {
		grp.AttachedPolicies = append(grp.AttachedPolicies, PolicyRef{
			ARN:  aws.ToString(p.PolicyArn),
			Name: aws.ToString(p.PolicyName),
		})
	}
	for _, ip := range g.GroupPolicyList {
		doc, err := parseURLEncodedPolicy(aws.ToString(ip.PolicyDocument))
		if err != nil {
			continue
		}
		grp.InlinePolicies = append(grp.InlinePolicies, InlinePolicy{
			Name:     aws.ToString(ip.PolicyName),
			Document: doc,
		})
	}
	return grp
}

func convertManagedPolicy(p types.ManagedPolicyDetail) (ManagedPolicy, error) {
	mp := ManagedPolicy{
		ARN:  aws.ToString(p.Arn),
		Name: aws.ToString(p.PolicyName),
	}
	for _, v := range p.PolicyVersionList {
		if v.IsDefaultVersion {
			doc, err := parseURLEncodedPolicy(aws.ToString(v.Document))
			if err != nil {
				return mp, err
			}
			mp.Document = doc
			break
		}
	}
	return mp, nil
}

func parseURLEncodedPolicy(encoded string) (PolicyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("url-decoding policy: %w", err)
	}
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return PolicyDocument{}, fmt.Errorf("parsing policy JSON: %w", err)
	}
	return doc, nil
}
