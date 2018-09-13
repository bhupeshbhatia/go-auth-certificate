package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/pkg/errors"
)

func main() {
	//certificate authority = CA
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{"Terrex Tech"},
			Country:      []string{"CA"},
			Province:     []string{"Ontario"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	//Creating RSA 2048 key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		if err != nil {
			err = errors.Wrap(err, "error generating private key")
			log.Println(err)
		}
	}
	publicKey := &privateKey.PublicKey

	//Getting certificate ready and self signing it
	certCreation, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		err = errors.Wrap(err, "certificate creation failed")
		log.Println(err)
		return
	}

	//Save public file
	publicCert, err := os.Create("ca.crt")
	pem.Encode(publicCert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certCreation,
	})
	publicCert.Close()
	log.Println("Written cert.pem\n")

	//Private Key
	privateCert, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(privateCert, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	privateCert.Close()
	log.Println("Written key.pem\n")

}
