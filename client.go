package linode

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/linode/linodego"
)

func (p *Provider) init(ctx context.Context) {
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

// trimTrailingDot trims any trailing "." from fqdn. Linode's API does not use FQDNs.
func trimTrailingDot(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

func (p *Provider) getDomainIDByZone(ctx context.Context, zone string) (int, error) {
	listOptions := linodego.NewListOptions(1, "")
	listOptions.Pages = listOptions.Page
	for page := listOptions.Pages; page <= listOptions.Pages; page++ {
		listOptions.Page = page
		domains, err := p.client.ListDomains(ctx, listOptions)
		if err != nil {
			return 0, fmt.Errorf("could not list domains: %v", err)
		}
		for _, d := range domains {
			if d.Domain == trimTrailingDot(zone) {
				return d.ID, nil
			}
		}
	}
	return 0, fmt.Errorf("could not find the domain provided")
}

func (p *Provider) getDomainRecords(ctx context.Context, zone string, domainID int) ([]libdns.Record, error) {
	listOptions := linodego.NewListOptions(0, "")
	linodeRecords, err := p.client.ListDomainRecords(ctx, domainID, listOptions)
	if err != nil {
		return nil, fmt.Errorf("could not list domain records: %v", err)
	}

	records := make([]libdns.Record, 0, len(linodeRecords))
	for _, rec := range linodeRecords {
		records = append(records, *convertToLibdns(zone, &rec))
	}

	return records, nil
}

func (p *Provider) createDomainRecord(ctx context.Context, zone string, domainID int, record *libdns.Record) (*libdns.Record, error) {
	newRec, err := p.client.CreateDomainRecord(ctx, domainID, linodego.DomainRecordCreateOptions{
		Type:   linodego.DomainRecordType(record.Type),
		Name:   libdns.RelativeName(record.Name, zone),
		Target: record.Value,
		TTLSec: int(record.TTL.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	return convertToLibdns(zone, newRec), nil
}

func (p *Provider) updateDomainRecord(ctx context.Context, zone string, domainID int, record *libdns.Record) (*libdns.Record, error) {
	recordID, err := strconv.Atoi(record.ID)
	if err != nil {
		return nil, err
	}
	updatedRec, err := p.client.UpdateDomainRecord(ctx, domainID, recordID, linodego.DomainRecordUpdateOptions{
		Type:   linodego.DomainRecordType(record.Type),
		Name:   libdns.RelativeName(record.Name, zone),
		Target: record.Value,
		TTLSec: int(record.TTL.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	return mergeWithExistingLibdns(zone, record, updatedRec), nil
}

func (p *Provider) deleteDomainRecord(ctx context.Context, domainID int, record *libdns.Record) error {
	recordID, err := strconv.Atoi(record.ID)
	if err != nil {
		return err
	}
	return p.client.DeleteDomainRecord(ctx, domainID, recordID)
}

func convertToLibdns(zone string, remoteRecord *linodego.DomainRecord) *libdns.Record {
	return mergeWithExistingLibdns(zone, nil, remoteRecord)
}

func mergeWithExistingLibdns(zone string, existingRecord *libdns.Record, remoteRecord *linodego.DomainRecord) *libdns.Record {
	if existingRecord == nil {
		existingRecord = &libdns.Record{}
	}
	existingRecord.ID = strconv.Itoa(remoteRecord.ID)
	existingRecord.Type = string(remoteRecord.Type)
	existingRecord.Name = libdns.RelativeName(remoteRecord.Name, zone)
	existingRecord.Value = remoteRecord.Target
	existingRecord.TTL = time.Duration(remoteRecord.TTLSec) * time.Second
	return existingRecord
}
