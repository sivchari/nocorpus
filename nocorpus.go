package nocorpus

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = "nocorpus is a analyzer that diagnoses fuzzing test of no corpus"

// Analyzer is an analyzer for nocorpus
var Analyzer = &analysis.Analyzer{
	Name: "nocorpus",
	Doc:  doc,
	Run:  run,
	Requires: []*analysis.Analyzer{
		inspect.Analyzer,
	},
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
	}

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if !strings.HasPrefix(n.Name.Name, "Fuzz") {
				return
			}
			list := n.Type.Params.List
			var variable string
			for _, l := range list {
				star, ok := l.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				if pass.TypesInfo.TypeOf(star).String() != "*testing.F" {
					continue
				}
				variable = l.Names[0].Name
			}
			if variable == "" {
				return
			}
			var m []struct{}
			for _, b := range n.Body.List {
				expr, ok := b.(*ast.ExprStmt)
				if !ok {
					continue
				}
				call, ok := expr.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				x, ok := selector.X.(*ast.Ident)
				if !ok {
					continue
				}
				if x.Name+"."+selector.Sel.Name == variable+"."+"Add" {
					m = append(m, struct{}{})
				}
			}
			if len(m) == 0 {
				pass.Reportf(n.Pos(), "There is no corpus on %s's fuzzing test.", n.Name.Name)
			}
		}
	})

	return nil, nil
}
