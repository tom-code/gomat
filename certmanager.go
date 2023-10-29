package gomat

import (
	"crypto/ecdsa"
	"crypto/x509"

)

// matter certificate manager interface
// all generated certificates must be compatible with matter
//   - this means that after they are reencoded to matter format and back their signature must match
type CertificateManager interface {
	// load previous state of certificate manager
	// this shall succeed even for first time
	Load()

	// bootstrap certificate authority - generate CA keys
	BootstrapCa()
	GetCaPublicKey() ecdsa.PublicKey
	GetCaCertificate() *x509.Certificate

	// CreateUser creates keys and certificate for node with specific id
	// it must be possible to later retrieve node keys using GetPrivkey and certificate using GetCertificate
	CreateUser(node_id uint64) error

	// retrieve certificate of specified node (previously created by CreateUser)
	GetCertificate(id uint64) *x509.Certificate

	// retrieve key of specified node (previously created by CreateUser)
	GetPrivkey(id uint64) *ecdsa.PrivateKey

	// create and sign certificate using local CA keys
	SignCertificate(user_pubkey *ecdsa.PublicKey, node_id uint64) (*x509.Certificate, error)
}
