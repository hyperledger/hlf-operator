package utils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

func ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	block, _ := pem.Decode(crlBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing CRL")
	}

	crl, err := x509.ParseCRL(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %v", err)
	}

	return crl, nil
}
