// Package linode implements a DNS record management client compatible
// with the libdns interfaces for Linode.
package linode

import (
	"context"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
	"github.com/linode/linodego"
)

// Provider facilitates DNS record manipulation with Linode.
type Provider struct {
	APIToken   string `json:"api_token,omitempty"`
	APIURL     string `json:"api_url,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
	client     linodego.Client
	once       sync.Once
	mutex      sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.init(ctx)

	domainID, err := p.getDomainIDByZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("could not find domain ID for zone: %s: %v", zone, err)
	}

	listOptions := linodego.NewListOptions(0, "")
	linodeRecords, err := p.client.ListDomainRecords(ctx, domainID, listOptions)
	if err != nil {
		return nil, fmt.Errorf("could not list domain records: %v", err)
	}

	records := make([]libdns.Record, 0, len(linodeRecords))
	for _, rec := range linodeRecords {
		records = p.appendRecord(zone, records, &rec)
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
		return nil, fmt.Errorf("could not find domain ID for zone: %s: %v", zone, err)
	}

	returnRecords := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rec, err := p.createDomainRecord(ctx, zone, domainID, &record)
		if err != nil {
			return nil, err
		}
		returnRecords = append(returnRecords, *rec)
	}

	return returnRecords, nil
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

	returnRecords := make([]libdns.Record, 0)

	for _, record := range records {
		if record.ID == "" {
			// Doesn't exist yet
			newRec, err := p.createDomainRecord(ctx, zone, domainID, &record)
			if err != nil {
				return nil, err
			}
			returnRecords = append(returnRecords, *newRec)
			continue
		}

		// Update the record
		newRec, err := p.updateDomainRecord(ctx, zone, domainID, &record)
		if err != nil {
			return nil, err
		}
		returnRecords = append(returnRecords, *newRec)
	}

	return returnRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.init(ctx)

	domainID, err := p.getDomainIDByZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("could not find domain ID for zone: %s: %v", zone, err)
	}

	deletedRecords := make([]libdns.Record, len(records))

	for _, rec := range records {
		err := p.deleteDomainRecord(ctx, domainID, &rec)
		if err != nil {
			return nil, err
		}

		deletedRecords = append(deletedRecords, rec)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
