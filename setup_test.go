package nftsync

import (
	"reflect"
	"testing"

	"github.com/coredns/caddy"
	nft "github.com/google/nftables"
)

func TestGetTableFamilyByName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantFam nft.TableFamily
		wantOk  bool
	}{
		{`valid inet`, `inet`, nft.TableFamilyINet, true},
		{`uppercase`, `IPv4`, nft.TableFamilyIPv4, true},
		{`mixed uppercase`, `Ipv6`, nft.TableFamilyIPv6, true},
		{`invalid`, `unknown`, 0, false},
		{`empty`, ``, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, ok := getTableFamilyByName(tt.input)
			if f != tt.wantFam || ok != tt.wantOk {
				t.Errorf("Expected (%v, %v) but found (%v, %v)", f, ok, tt.wantFam, tt.wantOk)
			}
		})
	}
}

type testNftsync struct {
	name          string
	input         string
	shouldErr     bool
	wantConn      reflect.Type
	wantFamily    nft.TableFamily
	wantTableName string
	wantMinttl    uint32
}

func setuptester(test testNftsync, t *testing.T) {
	t.Helper()

	c := caddy.NewTestController("dns", test.input)
	ns, err := nftSyncParse(c)
	if test.shouldErr && err == nil {
		t.Error("Expected error but found nil")
		return
	} else if !test.shouldErr && err != nil {
		t.Errorf("Expected no error but found error: %v", err)
		return
	}
	if test.shouldErr && err != nil {
		return
	}

	if reflect.TypeOf(ns.NetlinkConn) != test.wantConn {
		t.Errorf("Expected Conn %v but found: %v", test.wantConn, reflect.TypeOf(ns.NetlinkConn))
	}
	if ns.table.Name != test.wantTableName {
		t.Errorf("Expected Conn %v but found: %v", test.wantTableName, ns.table.Name)
	}
	if ns.minttl != test.wantMinttl {
		t.Errorf("Expected Conn %v but found: %v", test.wantMinttl, ns.minttl)
	}
}

func TestSetup(t *testing.T) {
	t.Run("without mocking socket", func(t *testing.T) {
		tests := []testNftsync{
			{`valid inet t`, `nftsync inet t`, false, reflect.TypeFor[*nft.Conn](), nft.TableFamilyINet, defaultTableName, defaultMinTTL},

			// fails
			// dont make ipv4 and ipv6 table
			{`missing ipv4 t`, `nftsync ipv4 t`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, defaultTableName, defaultMinTTL},
			{`missing ipv6 t`, `nftsync ipv6 t`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv6, defaultTableName, defaultMinTTL},
			{`debug typo`, `nftsync de inet t`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, defaultTableName, defaultMinTTL},
			{`debug typo and ttl specifying`, `nftsync de inet t 10`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, defaultTableName, 10},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				setuptester(tt, t)
			})
		}
	})

	t.Run("with mocking socket", func(t *testing.T) {
		tests := []testNftsync{

			{`check connection`, `nftsync debug inet t`, false, reflect.TypeFor[*NetlinkMock](), nft.TableFamilyINet, defaultTableName, defaultMinTTL},
			{`ipv4`, `nftsync debug ipv4 t`, false, reflect.TypeFor[*NetlinkMock](), nft.TableFamilyIPv4, defaultTableName, defaultMinTTL},
			{`ipv6`, `nftsync debug ipv6 t`, false, reflect.TypeFor[*NetlinkMock](), nft.TableFamilyIPv6, defaultTableName, defaultMinTTL},
			{`setting ttl`, `nftsync debug inet t 10`, false, reflect.TypeFor[*NetlinkMock](), nft.TableFamilyIPv6, defaultTableName, 10},

			//fails
			{`missing table`, `nftsync inet notfound`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, `notfound`, defaultMinTTL},
			{`ttl zero`, `nftsync debug inet t 0`, true, reflect.TypeFor[*NetlinkMock](), nft.TableFamilyIPv4, defaultTableName, 0},
			{`ttl nega`, `nftsync debug inet t -1`, true, reflect.TypeFor[*NetlinkMock](), nft.TableFamilyIPv4, defaultTableName, 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				setuptester(tt, t)
			})
		}
	})
}
