package nftsync

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	nft "github.com/google/nftables"
)

func TestAddUpdateElementMessage(t *testing.T) {
	ns := NewNetlinkFake()
	v4Set, v6Set, err := getDefaultSet(t, ns)
	if err != nil {
		t.Fatalf("failed get set: %v", err)
	}
	tests := []struct {
		name        string
		iSet        *nft.Set
		iElm        []nft.SetElement
		wantMessage []fakeSetMessage
		wantErr     bool
	}{
		{
			"v4set",
			v4Set,
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout}},
			[]fakeSetMessage{
				{
					Set:   v4Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout}},
					Flag:  destroy,
				},
				{
					Set:   v4Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout}},
					Flag:  add,
				},
			},
			false,
		},
		{
			"v6set",
			v6Set,
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute}},
			[]fakeSetMessage{
				{
					Set:   v6Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute}},
					Flag:  destroy,
				},
				{
					Set:   v6Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute}},
					Flag:  add,
				},
			},
			false,
		},
		{
			"set is nil",
			nil,
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout}},
			nil,
			false,
		},
		{
			"elm is nil",
			v4Set,
			nil,
			nil,
			false,
		},
		{
			"multi elems",
			v4Set,
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
				{Key: netip.MustParseAddr("1.1.1.2").AsSlice(), Timeout: defaultTimeout + time.Minute},
			},
			[]fakeSetMessage{
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("1.1.1.2").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: destroy,
				},
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("1.1.1.2").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: add,
				},
			},
			false,
		},
		{
			"mixed family",
			v4Set,
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
				{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute},
			},
			[]fakeSetMessage{
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: destroy,
				},
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: add,
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { ns.m = nil }()
			err := addUpdateElementMessage(ns, tt.iSet, tt.iElm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if diff := cmp.Diff(ns.m, tt.wantMessage, cmpopts.IgnoreFields(nft.Set{}, "KeyType", "DataType")); diff != "" {
				t.Error(diff)
			}
		})
	}
}
