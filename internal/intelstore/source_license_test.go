package intelstore

import (
	"context"
	"encoding/json"
	"testing"
)

func TestBootstrapMaliciousKeepsOpenSSFLicenseAndOriginals(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, close := fullSourceFixture(t, "malicious")
	defer close()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	header, e := s.explicitHeader(ctx, result.Generation)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.readRef(ctx, header.Descriptor, 4096)
	if e != nil {
		t.Fatal(e)
	}
	var descriptor generationDescriptor
	if json.Unmarshal(raw, &descriptor) != nil {
		t.Fatal("descriptor")
	}
	raw, e = s.readRef(ctx, descriptor.Provenance, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var receipt sourceReceipt
	if json.Unmarshal(raw, &receipt) != nil || len(receipt.Attributions) != 1 || receipt.Attributions[0].License != "Apache-2.0" || receipt.PublisherAuthentication != "not-established" {
		t.Fatal("publisher/license assurance conflated")
	}
	text, e := s.readRef(ctx, receipt.Attributions[0].Text, 32<<10)
	if e != nil || string(text) != string(openssfLicense) {
		t.Fatal("required full license text missing", e)
	}
}
