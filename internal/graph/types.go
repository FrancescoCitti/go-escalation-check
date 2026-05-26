package graph

type NodeKind string

const (
	NodeUser   NodeKind = "user"
	NodeRole   NodeKind = "role"
	NodeGroup  NodeKind = "group"
	NodePolicy NodeKind = "policy"
)

type EdgeKind string

const (
	EdgeAssumeRole      EdgeKind = "assume_role"
	EdgePassRole        EdgeKind = "pass_role"
	EdgeCreatePolicy    EdgeKind = "create_policy"
	EdgeAttachPolicy    EdgeKind = "attach_policy"
	EdgeCreateRole      EdgeKind = "create_role"
	EdgePutPolicy       EdgeKind = "put_policy"
	EdgeAddToGroup      EdgeKind = "add_to_group"
	EdgeCreateAccessKey EdgeKind = "create_access_key"
	EdgeUpdateLogin     EdgeKind = "update_login"
	EdgeMemberOf        EdgeKind = "member_of"
)

type Node struct {
	ID      string
	Name    string
	Kind    NodeKind
	IsAdmin bool
}

type Edge struct {
	From string
	To   string
	Kind EdgeKind
	Via  string
}

type Path struct {
	Steps []*Edge
}
