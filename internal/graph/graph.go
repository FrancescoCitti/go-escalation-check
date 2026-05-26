package graph

type Graph struct {
	Nodes map[string]*Node
	Adj   map[string][]*Edge
}

func New() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Adj:   make(map[string][]*Edge),
	}
}

func (g *Graph) AddNode(n *Node) {
	g.Nodes[n.ID] = n
}

func (g *Graph) AddEdge(e *Edge) {
	g.Adj[e.From] = append(g.Adj[e.From], e)
}

func (g *Graph) FindPaths(from string, isTarget func(*Node) bool) []Path {
	var paths []Path
	visited := make(map[string]bool)

	var dfs func(current string, current_path []*Edge)
	dfs = func(current string, currentPath []*Edge) {
		node, ok := g.Nodes[current]
		if !ok {
			return
		}
		if isTarget(node) && len(currentPath) > 0 {
			pathCopy := make([]*Edge, len(currentPath))
			copy(pathCopy, currentPath)
			paths = append(paths, Path{Steps: pathCopy})
			return
		}
		if visited[current] {
			return
		}
		visited[current] = true
		defer func() { visited[current] = false }()

		for _, edge := range g.Adj[current] {
			dfs(edge.To, append(currentPath, edge))
		}
	}

	dfs(from, nil)
	return paths
}

func (g *Graph) AdminNodes() []*Node {
	var admins []*Node
	for _, n := range g.Nodes {
		if n.IsAdmin {
			admins = append(admins, n)
		}
	}
	return admins
}
