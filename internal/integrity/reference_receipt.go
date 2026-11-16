package integrity

import (
	"encoding/base64"
)

// ReferenceCatalogReceipt is the compact private association emitted by an
// actually verified catalog. It is not an archive, publisher authentication or
// a substitute for the acquisition boundary. No public qualification bit exists.
type ReferenceCatalogReceipt struct {
	InstanceID  string
	Binding     [32]byte
	ObservedSRI string
}

func (c ReferenceCatalog) Receipt() ReferenceCatalogReceipt {
	if !c.verified {
		return ReferenceCatalogReceipt{}
	}
	return ReferenceCatalogReceipt{c.instanceID, c.bindingFingerprint, c.observedSRI}
}
func ValidateReferenceCatalogReceipt(b ReferenceBinding, r ReferenceCatalogReceipt) bool {
	if !b.usable || r.InstanceID != b.instanceID || r.Binding != b.fingerprint {
		return false
	}
	for _, digest := range b.expectedDigests {
		token := b.selectedAlgorithm + "-" + base64.StdEncoding.EncodeToString(digest)
		if token == r.ObservedSRI {
			return true
		}
	}
	return false
}
