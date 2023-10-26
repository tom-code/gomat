package main

// requirements:
// - create, manage, own CA certificate and private key
// - sign device certificate (no need to store?)
// - create/sign/own controller certificate and private key
//    - this is key of user accessing devices
//    - it can be admin or moreregular user
//    - we may want to support multiple of them

import (
	"crypto/ecdsa"
	"crypto/x509"

)

type CertificateManager interface {
	// load previous state of certificate manager
	// this shall succeed even for first time
	Load()

	// bootstrap certificate authority - generate CA keys
	BootstrapCa()
	GetCaPublicKey() ecdsa.PublicKey
	GetCaCertificate() *x509.Certificate

	CreateUser(node_id uint64)
	GetCertificate(id uint64) *x509.Certificate
	GetPrivkey(id uint64) *ecdsa.PrivateKey

	SignCertificate(user_pubkey *ecdsa.PublicKey, node_id uint64) *x509.Certificate
}
