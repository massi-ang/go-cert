package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic("Failed to parse certificate:" + err.Error())
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM
}

func GenCARoot() (*x509.Certificate, []byte, *rsa.PrivateKey) {
	if _, err := os.Stat("someFile"); err == nil {
		//read PEM and cert from file
	}
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().Add(10 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	rootCert, rootPEM := genCert(&rootTemplate, &rootTemplate, &priv.PublicKey, priv)
	return rootCert, rootPEM, priv
}

func GenDCA(RootCert *x509.Certificate, RootKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	var DCATemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "DCA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	DCACert, DCAPEM := genCert(&DCATemplate, RootCert, &priv.PublicKey, RootKey)
	return DCACert, DCAPEM, priv
}

func GenServerCert(DCACert *x509.Certificate, DCAKey *rsa.PrivateKey, commonName string) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	var ServerTemplate = x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: commonName},
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}

	ServerCert, ServerPEM := genCert(&ServerTemplate, DCACert, &priv.PublicKey, DCAKey)
	return ServerCert, ServerPEM, priv

}

func ParsePEMFiles(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	var b *pem.Block
	var err error

	rootCAPem, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	b, _ = pem.Decode(rootCAPem)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	rootKeyPem, err := ioutil.ReadFile(keyPath)
	b, _ = pem.Decode(rootKeyPem)
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func main() {
	var rootKeyPath = flag.String("keyPath", "", "The private rootCa Key")
	var rootCertPath = flag.String("caPath", "", "The ca path")
	var subKeyPath = flag.String("subKeyPath", "", "The sub private Key")
	var subCertPath = flag.String("subCaPath", "", "The sub cert path")
	var genCA = flag.Bool("genCA", false, "Generate a new CA")
	var genSubCA = flag.Bool("genSubCA", false, "Generate a new CA")
	var genDeviceCert = flag.Bool("genDevice", false, "Generate a device certificate")
	var commonName = flag.String("cn", "", "the device certificate common name")
	flag.Parse()

	var rootCert *x509.Certificate
	var rootCertPEM []byte
	var rootKey *rsa.PrivateKey

	if *genCA == true {
		rootCert, rootCertPEM, rootKey = GenCARoot()
		caPrivKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})
		fmt.Println(string(caPrivKey))
		ioutil.WriteFile("rootCA.key", caPrivKey, 0644)
		ioutil.WriteFile("rootCA.crt", rootCertPEM, 0644)
		fmt.Println("rootCert\n", string(rootCertPEM))
	}

	var DCACert *x509.Certificate
	var DCACertPEM []byte
	var DCAKey *rsa.PrivateKey

	if *genSubCA && ((rootCertPath != nil && rootKeyPath != nil) || (rootCert != nil && rootKey != nil)) {
		var err error
		if rootCert == nil || rootKey == nil {
			if rootCert, rootKey, err = ParsePEMFiles(*rootCertPath, *rootKeyPath); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		DCACert, DCACertPEM, DCAKey = GenDCA(rootCert, rootKey)
		dcaPrivKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(DCAKey)})
		ioutil.WriteFile("subCA.key", dcaPrivKey, 0644)
		ioutil.WriteFile("subCA.crt", DCACertPEM, 0644)
		fmt.Println("DCACert\n", string(DCACertPEM))
		fmt.Println(string(dcaPrivKey))
	}
	//verifyDCA(rootCert, DCACert)

	if *genDeviceCert && ((subCertPath != nil && subKeyPath != nil) || (DCACert != nil && DCAKey != nil)) {
		if DCACert == nil || DCAKey == nil {
			var err error
			if DCACert, DCAKey, err = ParsePEMFiles(*subCertPath, *subKeyPath); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		_, ServerPEM, ServerKey := GenServerCert(DCACert, DCAKey, *commonName)
		deviceKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ServerKey)})
		ioutil.WriteFile("device.key", deviceKey, 0644)
		ioutil.WriteFile("device.crt", ServerPEM, 0644)
		fmt.Println(string(deviceKey))
		fmt.Println("ServerPEM\n", string(ServerPEM))
	}
	//verifyLow(rootCert, DCACert, ServerCert)
}

func verifyDCA(root, dca *x509.Certificate) {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := dca.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	fmt.Println("DCA verified")
}

func verifyLow(root, DCA, child *x509.Certificate) {
	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	roots.AddCert(root)
	inter.AddCert(DCA)
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
	}

	if _, err := child.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	fmt.Println("Low Verified")
}
