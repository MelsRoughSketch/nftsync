package nametrie

import (
	"strings"
	"sync/atomic"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// node simple Trie implementation in Go
type node[T any] struct {
	children      map[string]*node[T]
	value         *T
	wildcardValue *T
}

// newNode creates and returns a new Trie node
func newNode[T any]() *node[T] {
	return &node[T]{children: make(map[string]*node[T])}
}

// getLabelSlice returns valid slice
// a.example.com. -> [a example com]
// If the root is specified return nil
func getLabels(domain string) ([]string, bool) {
	if domain == "" {
		return nil, false
	}

	nn := plugin.Name(domain).Normalize()

	if _, ok := dns.IsDomainName(nn); !ok {
		return nil, false
	}

	s := strings.Split(strings.Trim(nn, "."), ".")
	if len(s) == 1 && s[0] == "" {
		return nil, true
	}
	return s, true
}

func (n *node[T]) insert(domain string, val T) {
	labels, ok := getLabels(domain)
	if !ok {
		return
	}
	if labels == nil {
		// nil is root path
		n.value = &val
		return
	}
	// Insert labels in reverse order
	current := n
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if label == "*" {
			current.wildcardValue = &val
			return
		}

		// Create child node if it doesn't exist and move to it
		if _, exists := current.children[label]; !exists {
			current.children[label] = newNode[T]()
		}
		current = current.children[label]
	}
	current.value = &val
}

// TrieTree represents the root of the TrieTree structure
type TrieTree[T any] struct {
	current atomic.Pointer[node[T]]
}

func (t *TrieTree[T]) Build(config map[string]T) {
	root := newNode[T]()
	for domain, value := range config {
		root.insert(domain, value)
	}
	t.current.Store(root)
}

// Search looks for the domain in the Trie and returns all matching values
func (t *TrieTree[T]) Search(domain string) []T {
	root := t.current.Load()
	if root == nil {
		return nil
	}
	labels, ok := getLabels(domain)
	if !ok {
		return nil
	}
	var results []T
	current := root

	// Search labels in reverse order
	for i := len(labels) - 1; i >= 0; i-- {
		if current.wildcardValue != nil {
			results = append(results, *current.wildcardValue)
		}
		label := labels[i]
		nextNode, exists := current.children[label]
		if !exists {
			return results
		}
		current = nextNode
	}

	// Add wildcard value, if you don't want append wildcard value to results,
	// you can comment out the following block.
	// exp.: if the domain node is "a.example.com" and "*.example.com",
	// a query for "a.example.com",
	// you can get both "a.example.com" and "*.example.com" values.
	if current.wildcardValue != nil {
		results = append(results, *current.wildcardValue)
	}

	if current.value != nil {
		results = append(results, *current.value)
	}
	return results
}
