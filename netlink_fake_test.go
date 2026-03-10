package nftsync

import (
	"flag"
	"net/netip"
	"reflect"
	"testing"

	nft "github.com/google/nftables"
	"github.com/stretchr/testify/assert"
)

var enableSystemTest = flag.Bool("system_test", false, "Run tests that operate operate kernel")

func checkSysTest(t *testing.T) {
	if !*enableSystemTest {
		t.SkipNow()
	}
}

// Tests whether the fake's behavior is correct.

// isTrulyNil is a function that avoids evaluating typed nil
// and evaluates the value instead.
func isTrulyNil(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Chan, reflect.Func, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

func assertNil(t *testing.T, x any, y any) {
	t.Helper()
	if isTrulyNil(x) && isTrulyNil(y) {
		t.Logf("[TEST_INFO] return is nil, x: %+v, y: %+v\n", x, y)
		return
	}
	if !isTrulyNil(x) && !isTrulyNil(y) {
		t.Logf("[TEST_INFO] return is not nil, \nx: %+v\ny: %+v\n", x, y)
		return
	}
	t.Errorf("doesnt match: \nx: %+v\ny: %+v", x, y)
}

func assertPanic(t *testing.T, wantPanic bool) {
	t.Helper()
	r := recover()
	switch wantPanic {
	case true:
		if r == nil {
			t.Errorf("want panic %v but %v", wantPanic, r)
		}
	case false:
		if r != nil {
			t.Errorf("dont want panic but %v", r)
		}
	}
}

func getConns(t *testing.T) (n, f NetlinkConn) {
	t.Helper()

	n, err := NewConnector()
	if err != nil {
		t.Errorf("get error when init conn: %v", err)
		return
	}
	f = NewNetlinkFake()
	return
}

func TestListTableOfFamily(t *testing.T) {
	checkSysTest(t)
	n, f := getConns(t)
	tests := []struct {
		name  string
		iName string
		iFam  nft.TableFamily
	}{
		{`found table`, defaultTableName, nft.TableFamilyINet},
		{`missing table`, `notfound`, nft.TableFamilyINet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nt, nErr := n.ListTableOfFamily(tt.iName, tt.iFam)
			ft, fErr := f.ListTableOfFamily(tt.iName, tt.iFam)
			assertNil(t, nt, ft)
			assertNil(t, nErr, fErr)
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
	checkSysTest(t)
	n, f := getConns(t)

	// get the actual object
	table, err := getDefaultTable(t, n)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		iTable    *nft.Table
		iName     string
		wantPanic bool
	}{
		{`found set v4`, table, `s4`, false},
		{`found set v6`, table, `s6`, false},
		{`found set e`, table, `e`, false},
		{`missing set`, table, `snotfound`, false},
		{`table object is nil`, nil, `s4`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, nErr := func() (*nft.Set, error) {
				defer assertPanic(t, tt.wantPanic)
				return n.GetSetByName(tt.iTable, tt.iName)
			}()
			fs, fErr := func() (*nft.Set, error) {
				defer assertPanic(t, tt.wantPanic)
				return f.GetSetByName(tt.iTable, tt.iName)
			}()
			assertNil(t, ns, fs)
			assertNil(t, nErr, fErr)
		})
	}
}

func getElementSlice(t *testing.T) (v4, v6, mixed []nft.SetElement) {
	t.Helper()

	addrV4 := netip.MustParseAddr("192.0.2.1")
	addrV6 := netip.MustParseAddr("2001:db8::1")
	v4 = append(v4, nft.SetElement{Key: addrV4.AsSlice(), Timeout: defaultTimeout})
	v6 = append(v6, nft.SetElement{Key: addrV6.AsSlice(), Timeout: defaultTimeout})
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
	checkSysTest(t)
	n, f := getConns(t)

	// get the actual object
	s4, s6, err := getDefaultSet(t, n)
	if err != nil {
		t.Fatal(err)
	}

	v4Elm, v6Elm, mixed := getElementSlice(t)

	tests := []struct {
		name      string
		iSet      *nft.Set
		iVals     []nft.SetElement
		wantPanic bool
	}{
		{`destroy ipv4 from set v4`, s4, v4Elm, false},
		{`destroy ipv6 from set v6`, s6, v6Elm, false},
		{`destroy ip from invalid family(v4)`, s4, v6Elm, false},
		{`destroy ip from invalid family(v6)`, s6, v4Elm, false},
		{`destroy mixedip`, s4, mixed, false},
		{`set is nil`, nil, v6Elm, true},
		{`element is nil`, s4, nil, false},
		{`invalid ip`, s4, []nft.SetElement{{Key: []byte{1}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nErr := func() (err error) {
				defer assertPanic(t, tt.wantPanic)
				err = n.SetDestroyElements(tt.iSet, tt.iVals)
				return
			}()
			fErr := func() (err error) {
				defer assertPanic(t, tt.wantPanic)
				err = f.SetDestroyElements(tt.iSet, tt.iVals)
				return
			}()
			assertNil(t, nErr, fErr)
		})
	}
}

func TestSetAddElements(t *testing.T) {
	checkSysTest(t)
	n, f := getConns(t)

	// get the actual object
	// get the actual object
	s4, s6, err := getDefaultSet(t, n)
	if err != nil {
		t.Fatal(err)
	}

	v4Elm, v6Elm, mixed := getElementSlice(t)

	tests := []struct {
		name      string
		iSet      *nft.Set
		iVals     []nft.SetElement
		wantPanic bool
	}{
		{`add ipv4 from set v4`, s4, v4Elm, false},
		{`add ipv6 from set v6`, s6, v6Elm, false},
		{`add ip from invalid family(v4)`, s4, v6Elm, false},
		{`add ip from invalid family(v6)`, s6, v4Elm, false},
		{`add mixedip`, s4, mixed, false},
		{`set is nil`, nil, v6Elm, true},
		{`element is nil`, s4, nil, false},
		{`invalid ip`, s4, []nft.SetElement{{Key: []byte{1}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nErr := func() (err error) {
				defer assertPanic(t, tt.wantPanic)
				err = n.SetAddElements(tt.iSet, tt.iVals)
				return
			}()
			fErr := func() (err error) {
				defer assertPanic(t, tt.wantPanic)
				err = f.SetAddElements(tt.iSet, tt.iVals)
				return
			}()
			assertNil(t, nErr, fErr)
		})
	}
}

// TODO refactoring
func TestFlush(t *testing.T) {
	checkSysTest(t)
	n, f := getConns(t)

	// get the actual object
	nV4, nV6, err := getDefaultSet(t, n)
	if err != nil {
		t.Fatal(err)
	}

	fV4, fV6, err := getDefaultSet(t, f)
	if err != nil {
		t.Fatal(err)
	}

	v4Elm, v6Elm, mixed := getElementSlice(t)

	tests := []struct {
		name      string
		iSetV4    bool
		iVals     []nft.SetElement
		wantPanic bool
	}{
		{`flush ipv4 from set v4`, true, v4Elm, false},
		{`flush ipv6 from set v6`, false, v6Elm, false},
		{`flush ip from invalid family(v4)`, true, v6Elm, false},
		{`flush ip from invalid family(v6)`, false, v4Elm, false},
		{`flush mixedip`, true, mixed, false},
		{`message is empty`, true, nil, false},
		{`flush mixed empty message`, true, append(v4Elm, nft.SetElement{}), false},
		{`flush invalid ip`, true, []nft.SetElement{{Key: []byte{1}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.iVals != nil {
				if tt.iSetV4 {
					assert.NoError(t, n.SetDestroyElements(nV4, tt.iVals))
					assert.NoError(t, f.SetDestroyElements(fV4, tt.iVals))
					assert.NoError(t, n.SetAddElements(nV4, tt.iVals))
					assert.NoError(t, f.SetAddElements(fV4, tt.iVals))
				} else {
					assert.NoError(t, n.SetDestroyElements(nV6, tt.iVals))
					assert.NoError(t, f.SetDestroyElements(fV6, tt.iVals))
					assert.NoError(t, n.SetAddElements(nV6, tt.iVals))
					assert.NoError(t, f.SetAddElements(fV6, tt.iVals))
				}
			}

			nErr := func() (err error) {
				defer assertPanic(t, tt.wantPanic)
				err = n.Flush()
				return
			}()

			fErr := func() (err error) {
				defer assertPanic(t, tt.wantPanic)
				err = f.Flush()
				return
			}()
			assertNil(t, nErr, fErr)
		})
	}
}

func TestFlushPhantomSet(t *testing.T) {
	checkSysTest(t)
	_, m := getConns(t)

	// get the actual object
	table, err := getDefaultTable(t, m)
	if err != nil {
		log.Fatal(err)
	}

	// err when doing flush
	es, err := m.GetSetByName(table, phantomSetName)
	if err != nil {
		t.Fatalf("set s4 not found for testing: %v", err)
	}
	v4Elm, _, _ := getElementSlice(t)
	err = m.SetDestroyElements(es, v4Elm)
	if err != nil {
		t.Fatalf("failed set destroy message: %v", err)
	}

	s, err := m.GetSetByName(table, phantomSetName)
	if err != nil {
		t.Fatalf("set s4 not found for testing: %v", err)
	}
	err = m.SetDestroyElements(s, v4Elm)
	if err != nil {
		t.Fatalf("failed set destroy message: %v", err)
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
