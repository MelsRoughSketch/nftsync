package nametrie

import (
	"flag"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Ignores flags declared in other packages to simplify test execution.
var _ = flag.Bool("system_test", false, "")

func (n *node[T]) visualize(label string, depth int) {
	indent := strings.Repeat("  ", depth)
	info := ""
	if n.wildcardValue != nil {
		info += " [*.value: " + fmt.Sprintf("%v", *n.wildcardValue) + "]"
	}
	if n.value != nil {
		info += fmt.Sprintf(" [value:%v]", *n.value)
	}
	fmt.Printf("%s|-%s%s\n", indent, label, info)
	for childLabel, childNode := range n.children {
		childNode.visualize(childLabel, depth+1)
	}
}

// Visualize prints the structure of the TrieTree
func (t *TrieTree[T]) Visualize(label string, depth int) {
	root := t.current.Load()
	if root != nil {
		root.visualize(label, depth)
	}
}

func TestGetLabels(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantLabels []string
		wantOk     bool
	}{
		{`valid`, `example.com`, []string{"example", "com"}, true},
		{`leaf is space`, ` .example.com`, []string{" ", "example", "com"}, true},
		{`contains space`, `a. .ex ample.com`, []string{"a", " ", "ex ample", "com"}, true},
		{`root is space`, `example.com. `, []string{"example", "com", " "}, true},
		{`root only`, `.`, nil, true},
		{`all leaves`, `*.`, []string{"*"}, true},

		// fails
		{`null`, ``, nil, false},
		{`empty leaf`, `a..example.com`, nil, false},
		{`empty leaf`, `.example.com`, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ok := getLabels(tt.input)
			if !reflect.DeepEqual(tt.wantLabels, s) {
				t.Errorf("want %v but %v", tt.wantLabels, s)
			}
			if ok != tt.wantOk {
				t.Errorf("want %v but %v", tt.wantOk, ok)
			}
		})
	}
}

func TestNodeInsert(t *testing.T) {
	root := newNode[string]()
	root.insert("example.com", "val")

	if _, ok := root.children["com"]; !ok {
		t.Error("Expected 'com' node to exist")
	}
}

func TestConfigManagerSearch(t *testing.T) {
	tree := &TrieTree[int]{}
	config := map[string]int{
		"*.example.com.": 1,
		"example.com":    2,
		"*.example.org":  3,
		"tld":            4,
		".":              5,
		"*.":             6,

		"du p.example.com ": 8,
		"b..example.com":    9,
	}
	tree.Build(config)
	tree.Visualize("ROOT", 0)

	tests := []struct {
		name      string
		domain    string
		wantSlice []int
	}{
		{`hit`, "a.example.com", []int{1, 6}},
		{`normalized domain hit`, "a.example.com.", []int{1, 6}},
		{`multi hit`, "example.com", []int{1, 2, 6}},
		{`tld hit`, "tld", []int{4, 6}},
		{`root hit`, ".", []int{5, 6}},
		{`invalid`, "..", nil},
		{`whitespace`, "", nil},
	}

	opt := cmpopts.SortSlices(func(a, b int) bool {
		return a < b
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := tree.Search(tt.domain)
			t.Logf("result: %v\n", results)
			if diff := cmp.Diff(results, tt.wantSlice, opt); diff != "" {
				t.Errorf("want %v but:%v", tt.wantSlice, results)
			}
		})
	}
}
