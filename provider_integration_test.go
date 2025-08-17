//go:build integration

// To run these tests:
// go test ./... --tags=integration

package linode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/linode/linodego"
)

// setupProviderFromEnv reads configuration from environment variables and returns a Provider.
// Env vars:
//
//	LINODE_DNS_PAT     -> Provider.APIToken
//	LINODE_API_URL     -> Provider.APIURL
//	LINODE_API_VERSION -> Provider.APIVersion
func setupProviderFromEnv(t *testing.T) *Provider {
	t.Helper()

	pat := os.Getenv("LINODE_DNS_PAT")
	apiURL := os.Getenv("LINODE_API_URL")
	apiVersion := os.Getenv("LINODE_API_VERSION")

	if pat == "" {
		t.Skip("integration test skipped: LINODE_DNS_PAT is not set")
	}

	return &Provider{
		APIToken:   pat,
		APIURL:     apiURL,
		APIVersion: apiVersion,
	}
}

// newLinodeClientFromEnv constructs a linodego client with the same env config as the Provider.
func newLinodeClientFromEnv(t *testing.T) linodego.Client {
	t.Helper()
	pat := os.Getenv("LINODE_DNS_PAT")
	apiURL := os.Getenv("LINODE_API_URL")
	apiVersion := os.Getenv("LINODE_API_VERSION")
	if pat == "" {
		t.Skip("integration test skipped: LINODE_DNS_PAT is not set")
	}
	c := linodego.NewClient(nil)
	c.SetToken(pat)
	if apiURL != "" {
		c.SetBaseURL(apiURL)
	}
	if apiVersion != "" {
		c.SetAPIVersion(apiVersion)
	}
	return c
}

// randHex returns n random bytes hex-encoded.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// createDomainRecordOrDie creates a domain record and fails the test if there's an error.
func createDomainRecordOrDie(t *testing.T, c linodego.Client, domainID int, opts linodego.DomainRecordCreateOptions) {
	t.Helper()
	if _, err := c.CreateDomainRecord(context.Background(), domainID, opts); err != nil {
		t.Fatalf("failed to create domain record (type=%s name=%s): %v", string(opts.Type), opts.Name, err)
	}
}

// createDomainRecordsOrDie creates a domain record and fails the test if there's an error.
func createDomainRecordsOrDie(t *testing.T, c linodego.Client, zone string, domainID int, records []libdns.Record) {
	t.Helper()
	for _, record := range records {
		createOpts, err := convertToDomainRecord(record, zone)
		if err != nil {
			t.Fatalf("convertToDomainRecord returned error: %v", err)
		}
		createDomainRecordOrDie(t, c, domainID, createOpts)
	}
}

func makeTestDomainRecords(domain string) []libdns.Record {
	testDomains := []libdns.Record{
		// Add a diverse set of sample records within this zone.
		// A records
		libdns.Address{Name: "a1", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.1")},
		libdns.Address{Name: "a2", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.2")},
		libdns.Address{Name: "dup", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.10")},
		libdns.Address{Name: "dup", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.11")},
		libdns.Address{Name: "*", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.99")},
		// AAAA records
		libdns.Address{Name: "aaaa1", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "aaaa2", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "dup6", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::10")},
		libdns.Address{Name: "dup6", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::11")},
		libdns.Address{Name: "*.wld", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::99")},
		// TXT records (subdomain and root)
		libdns.TXT{Name: "txt1", TTL: 300 * time.Second, Text: "hello-libdns"},
		libdns.TXT{Name: "@", TTL: 300 * time.Second, Text: "root-text"},
		// CNAME record
		libdns.CNAME{Name: "www", TTL: 300 * time.Second, Target: fmt.Sprintf("a1.%s", domain)},
		// MX records
		libdns.MX{Name: "@", TTL: 300 * time.Second, Preference: 10, Target: fmt.Sprintf("mail.%s", domain)},
		// SRV records (common types)
		// _sip._tcp -> sipserver
		libdns.SRV{Name: "_sip._tcp", TTL: 300 * time.Second, Service: "sip", Transport: "tcp", Priority: 10, Weight: 5, Port: 5060, Target: fmt.Sprintf("sipserver.%s", domain)},
		// _xmpp-client._tcp -> xmpp
		libdns.SRV{Name: "_xmpp-client._tcp", TTL: 300 * time.Second, Service: "xmpp-client", Transport: "tcp", Priority: 20, Weight: 10, Port: 5222, Target: fmt.Sprintf("xmpp.%s", domain)},
		// CAA records for letsencrypt.org
		libdns.CAA{Name: "@", TTL: 300 * time.Second, Flags: 0, Tag: "iodef", Value: fmt.Sprintf("mailto:security@%s", domain)},
		libdns.CAA{Name: "letsencrypt", TTL: 300 * time.Second, Flags: 0, Tag: "issue", Value: "letsencrypt.org"},
		libdns.CAA{Name: "letsencryptwild", TTL: 300 * time.Second, Flags: 0, Tag: "issuewild", Value: "letsencrypt.org"},
	}
	return testDomains
}

// makeTestDomain creates a temporary domain and sample records, and registers cleanup to delete it.
// It returns the domain name and ID.
func makeTestDomain(t *testing.T, c linodego.Client) (string, int) {
	t.Helper()
	ctx := context.Background()

	suffix := time.Now().UTC().Format("20060102-150405") + "-" + randHex(4)
	domain := fmt.Sprintf("libdns-test-%s.example", suffix)

	// Create master domain; SOAEmail is required by Linode for master domains.
	d, err := c.CreateDomain(ctx, linodego.DomainCreateOptions{
		Domain:   domain,
		Type:     linodego.DomainTypeMaster,
		SOAEmail: "hostmaster@" + domain,
	})
	if err != nil {
		t.Fatalf("failed to create test domain %q: %v", domain, err)
	}

	// Ensure cleanup deletes the domain.
	t.Cleanup(func() {
		_ = c.DeleteDomain(context.Background(), d.ID)
	})

	return domain, d.ID
}

func assertPresent(t *testing.T, expected libdns.Record, haystack []libdns.Record) {
	t.Helper()
	exp := expected.RR()
	for _, actual := range haystack {
		act := actual.RR()
		if exp.Name == act.Name && exp.Type == act.Type && exp.TTL == act.TTL && exp.Data == act.Data {
			return
		}
	}
	t.Errorf("expected record not found in haystack: %+v", exp)
}

func assertAbsent(t *testing.T, expected libdns.Record, haystack []libdns.Record) {
	t.Helper()
	exp := expected.RR()
	for _, actual := range haystack {
		act := actual.RR()
		if exp.Name == act.Name && exp.Type == act.Type && exp.TTL == act.TTL && exp.Data == act.Data {
			t.Errorf("unexpected record found in haystack: %+v", exp)
		}
	}
}

func TestIntegration_ListZones(t *testing.T) {
	p := setupProviderFromEnv(t)
	c := newLinodeClientFromEnv(t)

	// Create a fresh domain for this test case.
	zone, domainID := makeTestDomain(t, c)
	createDomainRecordsOrDie(t, c, zone, domainID, makeTestDomainRecords(zone))

	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones returned error: %v", err)
	}

	found := false
	for _, z := range zones {
		if libdns.AbsoluteName("@", z.Name) == libdns.AbsoluteName("@", zone) || z.Name == zone {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find test zone %q in ListZones results", zone)
	}
	t.Logf("ListZones succeeded; found test zone %q among %d zones", zone, len(zones))
}

func TestIntegration_GetRecords(t *testing.T) {
	p := setupProviderFromEnv(t)
	c := newLinodeClientFromEnv(t)

	// Create a fresh domain and some records for this test case.
	zone, domainID := makeTestDomain(t, c)
	createDomainRecordsOrDie(t, c, zone, domainID, makeTestDomainRecords(zone))

	records, err := p.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords returned error for zone %q: %v", zone, err)
	}

	// Assert that our sample records are present.
	expectedRecords := makeTestDomainRecords(zone)
	seenRecords := make([]bool, len(records))
	for _, expected := range expectedRecords {
		t.Run(expected.RR().Data, func(t *testing.T) {
			exp := expected.RR()
			found := false
			for recI, actual := range records {
				act := actual.RR()
				if exp.Name == act.Name && exp.Type == act.Type && exp.TTL == act.TTL && exp.Data == act.Data {
					if seenRecords[recI] {
						t.Errorf("matched record with two expected records: record (%+v) in GetRecords results for zone %q", expected, zone)
					}
					found = true
					seenRecords[recI] = true
					break
				}
			}
			if !found {
				t.Errorf("expected to find record %+v in GetRecords results for zone %q", expected, zone)
			}
		})
	}
	// Assert that all no extra records were returned.
	for recI, seen := range seenRecords {
		if !seen {
			t.Errorf("record in GetRecords results not in expectedResults for zone %q: (%+v)", zone, records[recI])
		}
	}
	t.Logf("GetRecords succeeded for zone %q; found expected sample records", zone)
}

func TestIntegration_DeleteRecords(t *testing.T) {
	p := setupProviderFromEnv(t)
	c := newLinodeClientFromEnv(t)

	// Create a fresh domain and some records for this test case.
	zone, domainID := makeTestDomain(t, c)
	createDomainRecordsOrDie(t, c, zone, domainID, makeTestDomainRecords(zone))

	ctx := context.Background()

	// Build a set of deletions to exercise exact and wildcard semantics.
	toDelete := []libdns.Record{
		// Exact match delete: A a1 192.0.2.1 with TTL 300
		libdns.RR{Name: "a1", Type: "A", TTL: 300 * time.Second, Data: netip.MustParseAddr("192.0.2.1").String()},

		// Wildcard type/TTL/value: delete all records with name "dup"
		// (in our test data, these are two A records with different IPs)
		libdns.RR{Name: "dup"},

		// TTL wildcard for specific TXT record: delete txt1 (any TTL)
		libdns.RR{Name: "txt1", Type: "TXT", TTL: 0, Data: ""},

		// Delete the MX at zone root (name "@"), with wildcard TTL
		libdns.RR{Name: "@", Type: "MX"},
	}

	deleted, err := p.DeleteRecords(ctx, zone, toDelete)
	if err != nil {
		t.Fatalf("DeleteRecords returned error for zone %q: %v", zone, err)
	}

	// Collect deleted records by name+type for validation convenience.
	deletedMap := make(map[string][]libdns.RR)
	for _, rec := range deleted {
		rr := rec.RR()
		key := rr.Name + "|" + rr.Type
		deletedMap[key] = append(deletedMap[key], rr)
	}

	// We expect at least 5 records deleted:
	// - a1 A (exact) -> 1
	// - dup A (name wildcard) -> 2
	// - txt1 TXT -> 1
	// - @ MX -> 1
	if len(deleted) < 5 {
		t.Fatalf("expected at least 5 records to be deleted, got %d (deleted=%v)", len(deleted), deleted)
	}

	// Verify the expected specific deletions exist in the returned slice.
	// a1 A 192.0.2.1
	{
		key := "a1|A"
		found := false
		for _, rr := range deletedMap[key] {
			if rr.TTL == 300*time.Second && rr.Data == netip.MustParseAddr("192.0.2.1").String() {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected exact deletion of A a1 192.0.2.1 TTL 300s")
		}
	}
	// dup A should have 2 deletions regardless of IPs/TTLs when using wildcard input.
	if cnt := len(deletedMap["dup|A"]); cnt != 2 {
		t.Errorf("expected to delete 2 A records for name 'dup'; got %d", cnt)
	}
	// txt1 TXT should be deleted
	if len(deletedMap["txt1|TXT"]) != 1 {
		t.Errorf("expected to delete TXT record 'txt1'")
	}
	// root MX should be deleted (root is represented by '@')
	if len(deletedMap["@|MX"]) != 1 {
		t.Errorf("expected to delete MX record at root '@'")
	}

	// Now confirm via GetRecords that the deleted records are indeed gone,
	// and that unrelated records still exist.
	after, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after deletions returned error for zone %q: %v", zone, err)
	}

	// Helper to assert absence of a record in the current zone.
	assertAbsentWithWildcard := func(expected libdns.Record) {
		exp := expected.RR()
		for _, actual := range after {
			act := actual.RR()
			if exp.Name == act.Name && exp.Type == act.Type && (exp.TTL == 0 || exp.TTL == act.TTL) && (exp.Data == "" || exp.Data == act.Data) {
				t.Errorf("record should have been deleted but still present: %+v", exp)
				return
			}
		}
	}

	// Assert absence of those we intended to delete.
	assertAbsentWithWildcard(libdns.RR{Name: "a1", Type: "A", TTL: 300 * time.Second, Data: netip.MustParseAddr("192.0.2.1").String()})
	// For wildcard name-only deletions, ensure that no records with that name remain for type A.
	assertAbsentWithWildcard(libdns.RR{Name: "dup"})
	assertAbsentWithWildcard(libdns.RR{Name: "txt1", Type: "TXT"})
	assertAbsentWithWildcard(libdns.RR{Name: "@", Type: "MX"})

	// Sanity checks: unrelated records should still exist.
	// a2 A should remain
	assertPresent(t, libdns.Address{Name: "a2", TTL: 5 * time.Minute, IP: netip.MustParseAddr("192.0.2.2")}, after)
	// Root TXT should remain
	assertPresent(t, libdns.TXT{Name: "@", TTL: 5 * time.Minute, Text: "root-text"}, after)

	t.Logf("DeleteRecords succeeded for zone %q; expected records were deleted and unrelated records remain", zone)
}

func TestIntegration_AppendRecords(t *testing.T) {
	p := setupProviderFromEnv(t)
	c := newLinodeClientFromEnv(t)

	// Create a fresh domain for this test case (with baseline records).
	zone, domainID := makeTestDomain(t, c)
	createDomainRecordsOrDie(t, c, zone, domainID, makeTestDomainRecords(zone))
	ctx := context.Background()

	// Prepare a variety of records to append.
	newA := libdns.Address{Name: "newa", TTL: 2 * time.Minute, IP: netip.MustParseAddr("192.0.2.200")}
	newAAAA := libdns.Address{Name: "newaaaa", TTL: 5 * time.Minute, IP: netip.MustParseAddr("2001:db8::200")}
	newTXT := libdns.TXT{Name: "addtxt", TTL: 2 * time.Minute, Text: "hello-append"}
	newCNAME := libdns.CNAME{Name: "alias", TTL: 5 * time.Minute, Target: fmt.Sprintf("a1.%s", zone)}
	newMX := libdns.MX{Name: "@", TTL: 5 * time.Minute, Preference: 5, Target: fmt.Sprintf("mx.%s", zone)}
	newSRV := libdns.SRV{Service: "ldap", Transport: "tcp", Name: "_ldap._tcp", TTL: 5 * time.Minute, Priority: 10, Weight: 20, Port: 389, Target: fmt.Sprintf("ldap.%s", zone)}

	// Unsupported record type that should be skipped without failing.
	unsupported := libdns.ServiceBinding{Scheme: "https", Name: "@", TTL: 60 * time.Second, Priority: 1, Target: fmt.Sprintf("svc.%s", zone)}

	toAppend := []libdns.Record{newA, newAAAA, newTXT, newCNAME, newMX, newSRV, unsupported}

	added, err := p.AppendRecords(ctx, zone, toAppend)
	if err != nil {
		t.Fatalf("AppendRecords returned error for zone %q: %v", zone, err)
	}

	// We expect all supported records to be added; the unsupported one should be skipped.
	expectedSupported := []libdns.Record{newA, newAAAA, newTXT, newCNAME, newMX, newSRV}
	if len(added) != len(expectedSupported) {
		t.Fatalf("expected %d records to be added; got %d; added=%v", len(expectedSupported), len(added), added)
	}

	// Verify that each supported record appears in the returned slice
	for _, expected := range expectedSupported {
		assertPresent(t, expected, added)
	}

	// Now fetch all records and ensure our new records are present.
	all, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after append returned error for zone %q: %v", zone, err)
	}

	for _, expected := range expectedSupported {
		assertPresent(t, expected, all)
	}

	// Ensure the unsupported record was not created.
	assertAbsent(t, unsupported, all)

	// Try adding the same records again. Only types that permit identical records should be added.
	// In our case, this is TXT, MX, and SRV
	addedAgain, err := p.AppendRecords(ctx, zone, toAppend)
	if err != nil {
		t.Fatalf("AppendRecords returned error for zone %q: %v", zone, err)
	}
	if len(addedAgain) != 3 {
		t.Errorf("expected 3 records to be added; got %d", len(addedAgain))
	}

	t.Logf("AppendRecords succeeded for zone %q; supported records added and unsupported type skipped", zone)
}

func TestIntegration_SetRecords_Example1(t *testing.T) {
	p := setupProviderFromEnv(t)
	c := newLinodeClientFromEnv(t)
	ctx := context.Background()

	zone, domainID := makeTestDomain(t, c)

	// Ensure original zone has two root A records and a root TXT
	recordsPriorToSet := []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.1"), TTL: 5 * time.Minute},
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.2"), TTL: 5 * time.Minute},
		libdns.TXT{Name: "@", TTL: 5 * time.Minute, Text: "root-text"},
	}
	createDomainRecordsOrDie(t, c, zone, domainID, recordsPriorToSet)

	// Input: Set only one A at root to 192.0.2.3 with TTL 3600.
	input := []libdns.Record{
		libdns.Address{Name: "@", TTL: 3600 * time.Second, IP: netip.MustParseAddr("192.0.2.3")},
	}
	setRecords, err := p.SetRecords(ctx, zone, input)
	if err != nil {
		t.Fatalf("SetRecords returned error: %v", err)
	}

	// assert one set record
	if len(setRecords) != 1 {
		t.Fatalf("expected one set record, got %d", len(setRecords))
	}

	// Resultant zone: only A @ 192.0.2.3 remains for (Name=@,Type=A); other records unchanged.
	after, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after SetRecords error: %v", err)
	}

	if len(after) != 2 {
		t.Fatalf("expected 2 records after SetRecords, got %d", len(after))
	}

	// Assert that the expected records are present.
	for _, inputRec := range input {
		assertPresent(t, inputRec, after)
	}
	assertPresent(t, recordsPriorToSet[2], after) // The TXT
}

func TestIntegration_SetRecords_Example2(t *testing.T) {
	p := setupProviderFromEnv(t)
	c := newLinodeClientFromEnv(t)
	ctx := context.Background()

	zone, domainID := makeTestDomain(t, c)

	//
	//	;; Original zone
	//	alpha.example.com. 3600 IN AAAA 2001:db8::1
	//	alpha.example.com. 3600 IN AAAA 2001:db8::2
	//	beta.example.com.  3600 IN AAAA 2001:db8::3
	//	beta.example.com.  3600 IN AAAA 2001:db8::4
	//
	recordsPriorToSet := []libdns.Record{
		libdns.Address{Name: "alpha", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "alpha", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "beta", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::3")},
		libdns.Address{Name: "beta", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::4")},
	}
	createDomainRecordsOrDie(t, c, zone, domainID, recordsPriorToSet)

	//
	//	;; Input
	//	alpha.example.com. 3600 IN AAAA 2001:db8::1
	//	alpha.example.com. 3600 IN AAAA 2001:db8::2
	//	alpha.example.com. 3600 IN AAAA 2001:db8::5
	//
	input := []libdns.Record{
		libdns.Address{Name: "alpha", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "alpha", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "alpha", TTL: 3600 * time.Second, IP: netip.MustParseAddr("2001:db8::5")},
	}
	setRecords, err := p.SetRecords(ctx, zone, input)
	if err != nil {
		t.Fatalf("SetRecords returned error: %v", err)
	}
	// should have set 3 records for alpha AAAA
	if len(setRecords) != 3 {
		t.Fatalf("expected 3 set records, got %d", len(setRecords))
	}

	//
	//	;; Resultant zone
	//	alpha.example.com. 3600 IN AAAA 2001:db8::1
	//	alpha.example.com. 3600 IN AAAA 2001:db8::2
	//	alpha.example.com. 3600 IN AAAA 2001:db8::5
	//	beta.example.com.  3600 IN AAAA 2001:db8::3
	//	beta.example.com.  3600 IN AAAA 2001:db8::4
	//
	after, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after SetRecords error: %v", err)
	}

	// We expect exactly 5 records in the zone now
	if len(after) != 5 {
		t.Fatalf("expected 5 records after SetRecords, got %d", len(after))
	}

	// Assert that expected records are present
	for _, inputRec := range input {
		assertPresent(t, inputRec, after)
	}
	assertPresent(t, recordsPriorToSet[2], after) // beta ::3
	assertPresent(t, recordsPriorToSet[3], after) // beta ::4
}
