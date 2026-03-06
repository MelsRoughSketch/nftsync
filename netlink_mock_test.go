package nftsync

import (
	"net/netip"
	"testing"

	nft "github.com/google/nftables"
)

// Tests whether the mock's behavior is correct.

func assertErr(t *testing.T, err1 error, err2 error) {
	t.Helper()
	if err1 == nil && err2 == nil {
		t.Log("return is nil")
		return
	}
	if err1 != nil && err2 != nil {
		t.Log("return is not nil")
		return
	}
	t.Errorf("error doesnt match: %v, %v", err1, err2)
}

func assertPanic(t *testing.T, wantpanic bool) {
	t.Helper()
	r := recover()
	switch wantpanic {
	case true:
		if r == nil {
			t.Errorf("want panic %v but %v", wantpanic, r)
		}
	case false:
		if r != nil {
			t.Errorf("dont want panic but %v", r)
		}
	}
}

func getConns(t *testing.T) (n, m NetlinkConn) {
	t.Helper()

	n, err := NewConnector()
	if err != nil {
		t.Errorf("get error when init conn: %v", err)
		return
	}
	m = NewNetlinkMock()
	return
}

func TestListTableOfFamily(t *testing.T) {
	n, m := getConns(t)
	tests := []struct {
		name  string
		iName string
		iFam  nft.TableFamily
	}{
		{`found table`, defaultTableName, nft.TableFamilyINet},
		{`not found table`, `notfound`, nft.TableFamilyINet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, nerr := n.ListTableOfFamily(tt.iName, tt.iFam)
			_, merr := m.ListTableOfFamily(tt.iName, tt.iFam)
			assertErr(t, nerr, merr)
		})
	}
}

func getDefaultTable(t *testing.T, c NetlinkConn) (table *nft.Table, err error) {
	t.Helper()

	table, err = c.ListTableOfFamily(defaultTableName, defaultTableFamily)
	if err != nil {
		t.Errorf("table inet t not found for testing: %v", err)
	}
	return
}

func TestGetSetByName(t *testing.T) {
	n, m := getConns(t)

	// get the actual object
	table, err := getDefaultTable(t, n)
	if err != nil {
		return
	}

	tests := []struct {
		name      string
		iTable    *nft.Table
		iName     string
		wantpanic bool
	}{
		{`found set v4`, table, `s4`, false},
		{`found set v6`, table, `s6`, false},
		{`found set e`, table, `e`, false},
		{`not found set`, table, `snotfound`, false},
		{`table object is nil`, nil, `s4`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nerr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				_, err = n.GetSetByName(tt.iTable, tt.iName)
				return
			}()
			merr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				_, err = m.GetSetByName(tt.iTable, tt.iName)
				return
			}()
			assertErr(t, nerr, merr)
		})
	}
}

func getElementSlice(t *testing.T) (v4, v6, mixed []nft.SetElement) {
	t.Helper()

	addrv4 := netip.MustParseAddr("1.1.1.1")
	addrv6 := netip.MustParseAddr("1::1")
	v4 = append(v4, nft.SetElement{Key: addrv4.AsSlice(), Timeout: defaultTimeout})
	v6 = append(v6, nft.SetElement{Key: addrv6.AsSlice(), Timeout: defaultTimeout})
	mixed = append(mixed, v4[0], v6[0])
	return
}

func getDefaultSet(t *testing.T, c NetlinkConn) (*nft.Set, *nft.Set, error) {
	t.Helper()

	table, err := getDefaultTable(t, c)
	if err != nil {
		return nil, nil, err
	}
	s4, err := c.GetSetByName(table, defaultSetV4Name)
	if err != nil {
		t.Errorf("set s4 not found for testing: %v", err)
		return nil, nil, err
	}

	s6, err := c.GetSetByName(table, defaultSetV6Name)
	if err != nil {
		t.Errorf("set s6 not found for testing: %v", err)
		return nil, nil, err
	}
	return s4, s6, nil
}

func TestSetDestroyElements(t *testing.T) {
	n, m := getConns(t)

	// get the actual object
	s4, s6, err := getDefaultSet(t, n)
	if err != nil {
		return
	}

	v4elm, v6elm, mixed := getElementSlice(t)

	tests := []struct {
		name      string
		iSet      *nft.Set
		iVals     []nft.SetElement
		wantpanic bool
	}{
		{`destroy ipv4 from set v4`, s4, v4elm, false},
		{`destroy ipv6 from set v6`, s6, v6elm, false},
		{`destroy ip from invalid family(v4)`, s4, v6elm, false},
		{`destroy ip from invalid family(v6)`, s6, v4elm, false},
		{`destroy mixedip`, s4, mixed, false},
		{`set is nil`, nil, v6elm, true},
		{`element is nil`, s4, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nerr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				err = n.SetDestroyElements(tt.iSet, tt.iVals)
				return
			}()
			merr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				err = m.SetDestroyElements(tt.iSet, tt.iVals)
				return
			}()
			assertErr(t, nerr, merr)
		})
	}
}

func TestSetAddElements(t *testing.T) {
	n, m := getConns(t)

	// get the actual object
	// get the actual object
	s4, s6, err := getDefaultSet(t, n)
	if err != nil {
		return
	}

	v4elm, v6elm, mixed := getElementSlice(t)

	tests := []struct {
		name      string
		iSet      *nft.Set
		iVals     []nft.SetElement
		wantpanic bool
	}{
		{`add ipv4 from set v4`, s4, v4elm, false},
		{`add ipv6 from set v6`, s6, v6elm, false},
		{`add ip from invalid family(v4)`, s4, v6elm, false},
		{`add ip from invalid family(v6)`, s6, v4elm, false},
		{`add mixedip`, s4, mixed, false},
		{`set is nil`, nil, v6elm, true},
		{`element is nil`, s4, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nerr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				err = n.SetAddElements(tt.iSet, tt.iVals)
				return
			}()
			merr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				err = m.SetAddElements(tt.iSet, tt.iVals)
				return
			}()
			assertErr(t, nerr, merr)
		})
	}
}

// TODO refactering
func TestFlush(t *testing.T) {
	n, m := getConns(t)

	// get the actual object
	nv4, nv6, err := getDefaultSet(t, n)
	if err != nil {
		return
	}

	mv4, mv6, err := getDefaultSet(t, m)
	if err != nil {
		return
	}

	v4elm, v6elm, mixed := getElementSlice(t)

	tests := []struct {
		name      string
		iSetV4    bool
		iVals     []nft.SetElement
		wantpanic bool
	}{
		{`flush ipv4 from set v4`, true, v4elm, false},
		{`flush ipv6 from set v6`, false, v6elm, false},
		{`flush ip from invalid family(v4)`, true, v6elm, false},
		{`flush ip from invalid family(v6)`, false, v4elm, false},
		{`flush mixedip`, true, mixed, false},
		{`message is empty`, true, nil, false},
		{`flush mixed empty message`, true, append(v4elm, nft.SetElement{}), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.iVals != nil {
				if tt.iSetV4 {
					n.SetDestroyElements(nv4, tt.iVals)
					m.SetDestroyElements(mv4, tt.iVals)
					n.SetAddElements(nv4, tt.iVals)
					m.SetAddElements(mv4, tt.iVals)
				} else {
					n.SetDestroyElements(nv6, tt.iVals)
					m.SetDestroyElements(mv6, tt.iVals)
					n.SetAddElements(nv6, tt.iVals)
					m.SetAddElements(mv6, tt.iVals)
				}
			}

			nerr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				err = n.Flush()
				return
			}()

			merr := func() (err error) {
				defer assertPanic(t, tt.wantpanic)
				err = m.Flush()
				return
			}()
			assertErr(t, nerr, merr)
		})
	}
}

func TestFlushPhantomSet(t *testing.T) {
	_, m := getConns(t)

	// get the actual object
	table, err := getDefaultTable(t, m)
	if err != nil {
		return
	}

	// err when doing flush
	es, err := m.GetSetByName(table, phantomSetName)
	if err != nil {
		t.Errorf("set s4 not found for testing: %v", err)
	}
	v4elm, _, _ := getElementSlice(t)
	err = m.SetDestroyElements(es, v4elm)
	if err != nil {
		t.Errorf("failed set destroy message: %v", err)
	}

	s, err := m.GetSetByName(table, phantomSetName)
	if err != nil {
		t.Errorf("set s4 not found for testing: %v", err)
	}
	err = m.SetDestroyElements(s, v4elm)
	if err != nil {
		t.Errorf("failed set destroy message: %v", err)
	}

	t.Run(`flush phantom set`, func(t *testing.T) {
		err = m.Flush()
		if err == nil {
			t.Errorf(`want err but get nil: %v`, err)
		}
	})

	t.Run(`flush normal set`, func(t *testing.T) {
		err = m.Flush()
		if err != nil {
			t.Errorf(`want err but get nil: %v`, err)
		}
	})
}
