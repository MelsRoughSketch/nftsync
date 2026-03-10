package nftsync

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	nft "github.com/google/nftables"
)

func TestGetTTLConverter(t *testing.T) {
	tests := []struct {
		name   string
		minTTL uint32
		input  uint32
		want   time.Duration
	}{
		{
			name:   "input is smaller than minttl",
			minTTL: defaultMinTTL,
			input:  3,
			want:   time.Duration(defaultMinTTL+TimeoutOffset) * time.Second,
		},
		{
			name:   "input is the same as minttl",
			minTTL: defaultMinTTL,
			input:  defaultMinTTL,
			want:   time.Duration(defaultMinTTL+TimeoutOffset) * time.Second,
		},
		{
			name:   "input is bigger than minttl",
			minTTL: defaultMinTTL,
			input:  20,
			want:   time.Duration(20+TimeoutOffset) * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := getTTLConverter(tt.minTTL)
			got := converter(tt.input)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// treeStab implements Tree
type treeStab struct {
	s []ipSet
}

func (t *treeStab) Build(m map[string]ipSet) {}
func (t *treeStab) SetStab(s []ipSet)        { t.s = s }
func (t *treeStab) Search(_ string) []ipSet  { return t.s }
func NewStabTree() *treeStab                 { return &treeStab{} }

// for mocking addUpdateElementFunc
type UpdaterMockArg struct {
	S *nft.Set
	E []nft.SetElement
}

type UpdaterMock struct {
	Args   []UpdaterMockArg
	RetErr error
}

func (m *UpdaterMock) SetReturn(err error) { m.RetErr = err }
func (m *UpdaterMock) Do(_ NetlinkConn, s *nft.Set, e []nft.SetElement) error {
	if m.RetErr == nil {
		m.Args = append(m.Args, UpdaterMockArg{s, e})
	}

	return m.RetErr
}

func TestUpdateSetByNames(t *testing.T) {
	ou := addUpdateElementFunc
	defer func() { addUpdateElementFunc = ou }()

	ns := NewNftSync()
	ns.SetConn(NewNetlinkFake())

	tests := []struct {
		name       string
		iNames     []string
		iV4        []nft.SetElement
		iV6        []nft.SetElement
		StabReturn []ipSet
		mockReturn error
		wantArgs   []UpdaterMockArg
		wantErr    bool
	}{
		{
			"valid",
			[]string{""},
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			[]ipSet{{&nft.Set{Name: "4"}, &nft.Set{Name: "6"}}},
			nil,
			[]UpdaterMockArg{
				{
					&nft.Set{Name: "4"},
					[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
				},
				{
					&nft.Set{Name: "6"},
					[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
				},
			},
			false,
		},
		{
			"multi set",
			[]string{""},
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			[]ipSet{
				{&nft.Set{Name: "4"}, &nft.Set{Name: "6"}},
				{&nft.Set{Name: "4_2"}, &nft.Set{Name: "6_2"}},
			},
			nil,
			[]UpdaterMockArg{
				{
					&nft.Set{Name: "4"},
					[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
				},
				{
					&nft.Set{Name: "6"},
					[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
				},
				{
					&nft.Set{Name: "4_2"},
					[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
				},
				{
					&nft.Set{Name: "6_2"},
					[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
				},
			},
			false,
		},
		{
			"multi name",
			[]string{"", ""},
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			[]ipSet{
				{&nft.Set{Name: "4"}, &nft.Set{Name: "6"}},
			},
			nil,
			[]UpdaterMockArg{
				{
					&nft.Set{Name: "4"},
					[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
				},
				{
					&nft.Set{Name: "6"},
					[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
				},
				{
					&nft.Set{Name: "4"},
					[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
				},
				{
					&nft.Set{Name: "6"},
					[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
				},
			},
			false,
		},
		{
			"nil names",
			nil,
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			[]ipSet{
				{&nft.Set{Name: "4"}, &nft.Set{Name: "6"}},
			},
			nil,
			nil,
			false,
		},
		{
			"search returns nil",
			[]string{""},
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			nil,
			nil,
			nil,
			false,
		},

		{
			"err",
			[]string{""},
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			[]ipSet{
				{&nft.Set{Name: "4"}, &nft.Set{Name: "6"}},
			},
			errors.New("err"),
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := UpdaterMock{}
			mock.SetReturn(tt.mockReturn)
			addUpdateElementFunc = mock.Do
			tree := NewStabTree()
			tree.SetStab(tt.StabReturn)
			ns.SetTree(tree)

			err := updateSetByNames(ns, tt.iNames, tt.iV4, tt.iV6)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if diff := cmp.Diff(tt.wantArgs, mock.Args, cmpopts.IgnoreFields(nft.Set{}, "KeyType", "DataType")); diff != "" {
				t.Error(diff)
			}
		})
	}

}
