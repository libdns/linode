// Package linode implements a DNS record management client compatible
// with the libdns interfaces for Linode.
package linode

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/libdns/libdns"
	"github.com/linode/linodego"
)

// Provider facilitates DNS record manipulation with Linode.
type Provider struct {
	// APIToken is the Linode Personal Access Token, see https://cloud.linode.com/profile/tokens.
	APIToken string `json:"api_token,omitempty"`
	// APIURL is the Linode API hostname, i.e. "api.linode.com".
	APIURL string `json:"api_url,omitempty"`
	// APIVersion is the Linode API version, i.e. "v4".
	APIVersion string `json:"api_version,omitempty"`
	client     linodego.Client
	once       sync.Once
	mutex      sync.Mutex
}

func (p *Provider) init(_ context.Context) {
	p.once.Do(func() {
		p.client = linodego.NewClient(http.DefaultClient)
		if p.APIToken != "" {
			p.client.SetToken(p.APIToken)
		}
		if p.APIURL != "" {
			p.client.SetBaseURL(p.APIURL)
		}
		if p.APIVersion != "" {
			p.client.SetAPIVersion(p.APIVersion)
		}
	})
}

// ListZones lists all the zones (domains).
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)
	domains, err := p.client.ListDomains(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error listing domains: %w", err)
	}
	zones := make([]libdns.Zone, 0, len(domains))
	for _, domain := range domains {
		zones = append(zones, libdns.Zone{Name: domain.Domain})
	}
	return zones, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)
	domainID, err := p.getDomainIDByZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("error getting domain ID for zone %s: %v", zone, err)
	}
	records, err := p.listDomainRecords(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("error listing domain records: %w", err)
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)
	domainID, err := p.getDomainIDByZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("error getting domain ID for zone %s: %v", zone, err)
	}
	addedRecords := make([]libdns.Record, 0)
	for _, record := range records {
		addedRecord, err := p.createDomainRecord(ctx, zone, domainID, record)
		if err != nil {
			if errors.Is(err, ErrUnsupportedType) {
				// I would rather not fail silently, and no logger is provided by this interface, so just print the error.
				fmt.Printf("skipping unsupported record type: %v\n", err)
				continue
			}
			fmt.Printf("skipping record due to error: %v\n", err)
			continue
		}
		addedRecords = append(addedRecords, addedRecord)
	}
	return addedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)
	domainID, err := p.getDomainIDByZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("could not find domain ID for zone: %s: %v", zone, err)
	}
	setRecords, err := p.createOrUpdateDomainRecords(ctx, zone, domainID, records)
	if err != nil {
		return nil, fmt.Errorf("could not create or update domain records: %w", err)
	}
	return setRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
// As per the libdns interface, any deleted records must match exactly the input record (Name, Type, TTL, Value).
// If any of (Type, TTL, Value) are "", 0, or "", respectively, deleteDomainRecord will delete any records that match
// the other fields, regardless of the value of the fields that were left empty.
// Note: this does not apply to the Name field.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)
	domainID, err := p.getDomainIDByZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("error getting domain ID for zone %s: %v", zone, err)
	}
	deletedRecords, err := p.deleteDomainRecords(ctx, domainID, records)
	if err != nil {
		return nil, fmt.Errorf("error deleting domain records: %w", err)
	}
	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
