package escalation

type Technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Required    []string `json:"required_actions"`
	MitreKey    string   `json:"-"`
	Severity    string   `json:"severity"`
}

var Techniques = []Technique{
	{
		ID:          "create_new_policy_version",
		Name:        "Create New Policy Version",
		Description: "Create a new policy version with administrator permissions on an attached managed policy",
		Required:    []string{"iam:CreatePolicyVersion"},
		MitreKey:    "create_policy_version",
		Severity:    "critical",
	},
	{
		ID:          "set_default_policy_version",
		Name:        "Set Default Policy Version",
		Description: "Revert a managed policy to a prior version that granted administrator access",
		Required:    []string{"iam:SetDefaultPolicyVersion"},
		MitreKey:    "create_policy_version",
		Severity:    "high",
	},
	{
		ID:          "attach_user_policy",
		Name:        "Attach Admin Policy to User",
		Description: "Attach AdministratorAccess (or equivalent) directly to a user",
		Required:    []string{"iam:AttachUserPolicy"},
		MitreKey:    "attach_policy",
		Severity:    "critical",
	},
	{
		ID:          "attach_group_policy",
		Name:        "Attach Admin Policy to Group",
		Description: "Attach AdministratorAccess to a group you belong to",
		Required:    []string{"iam:AttachGroupPolicy"},
		MitreKey:    "attach_policy",
		Severity:    "critical",
	},
	{
		ID:          "attach_role_policy",
		Name:        "Attach Admin Policy to Role",
		Description: "Attach AdministratorAccess to a role you can assume",
		Required:    []string{"iam:AttachRolePolicy"},
		MitreKey:    "attach_policy",
		Severity:    "critical",
	},
	{
		ID:          "put_user_policy",
		Name:        "Put Inline Admin Policy on User",
		Description: "Inject an inline policy granting administrator access to a user",
		Required:    []string{"iam:PutUserPolicy"},
		MitreKey:    "put_policy",
		Severity:    "critical",
	},
	{
		ID:          "put_group_policy",
		Name:        "Put Inline Admin Policy on Group",
		Description: "Inject an inline policy granting administrator access to a group",
		Required:    []string{"iam:PutGroupPolicy"},
		MitreKey:    "put_policy",
		Severity:    "critical",
	},
	{
		ID:          "put_role_policy",
		Name:        "Put Inline Admin Policy on Role",
		Description: "Inject an inline policy granting administrator access to a role",
		Required:    []string{"iam:PutRolePolicy"},
		MitreKey:    "put_policy",
		Severity:    "critical",
	},
	{
		ID:          "create_access_key",
		Name:        "Create Access Key for Admin User",
		Description: "Generate programmatic credentials for a user with administrator privileges",
		Required:    []string{"iam:CreateAccessKey"},
		MitreKey:    "create_access_key",
		Severity:    "high",
	},
	{
		ID:          "create_login_profile",
		Name:        "Create Console Login for Admin User",
		Description: "Enable console access for a user that already has administrator privileges",
		Required:    []string{"iam:CreateLoginProfile"},
		MitreKey:    "update_login",
		Severity:    "high",
	},
	{
		ID:          "update_login_profile",
		Name:        "Reset Admin User Password",
		Description: "Change the console password of a user with administrator privileges",
		Required:    []string{"iam:UpdateLoginProfile"},
		MitreKey:    "update_login",
		Severity:    "high",
	},
	{
		ID:          "add_user_to_group",
		Name:        "Add Self to Admin Group",
		Description: "Add a user to a group that has administrator permissions",
		Required:    []string{"iam:AddUserToGroup"},
		MitreKey:    "add_to_group",
		Severity:    "critical",
	},
	{
		ID:          "update_assume_role_policy",
		Name:        "Backdoor Role Trust Policy",
		Description: "Modify a role's trust policy to grant yourself assume-role access",
		Required:    []string{"iam:UpdateAssumeRolePolicy"},
		MitreKey:    "assume_role",
		Severity:    "critical",
	},
	{
		ID:          "pass_role_ec2",
		Name:        "Pass Admin Role via EC2",
		Description: "Launch an EC2 instance with an admin IAM role and execute commands through it",
		Required:    []string{"iam:PassRole", "ec2:RunInstances"},
		MitreKey:    "pass_role",
		Severity:    "high",
	},
	{
		ID:          "pass_role_lambda",
		Name:        "Pass Admin Role via Lambda",
		Description: "Create and invoke a Lambda function with an admin role to execute arbitrary code",
		Required:    []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
		MitreKey:    "pass_role",
		Severity:    "high",
	},
	{
		ID:          "pass_role_cloudformation",
		Name:        "Pass Admin Role via CloudFormation",
		Description: "Create a CloudFormation stack that uses an admin role to provision resources",
		Required:    []string{"iam:PassRole", "cloudformation:CreateStack"},
		MitreKey:    "pass_role",
		Severity:    "high",
	},
	{
		ID:          "pass_role_glue",
		Name:        "Pass Admin Role via Glue",
		Description: "Create a Glue development endpoint with an admin role attached",
		Required:    []string{"iam:PassRole", "glue:CreateDevEndpoint"},
		MitreKey:    "pass_role",
		Severity:    "medium",
	},
	{
		ID:          "create_admin_role",
		Name:        "Create and Assume New Admin Role",
		Description: "Create a new IAM role, attach AdministratorAccess, then assume it",
		Required:    []string{"iam:CreateRole", "iam:AttachRolePolicy"},
		MitreKey:    "create_role",
		Severity:    "critical",
	},
}
