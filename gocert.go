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
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().Add(10 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	rootCert, rootPEM := genCert(&rootTemplate, &rootTemplate, &priv.PublicKey, priv)
	return rootCert, rootPEM, priv
}

func GenSubCA(RootCert *x509.Certificate, RootKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	var SubCATemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "SubCA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().Add(2 * time.Minute),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}
	SubCACert, SubCAPEM := genCert(&SubCATemplate, RootCert, &priv.PublicKey, RootKey)
	return SubCACert, SubCAPEM, priv
}

func GenDeviceCert(SubCACert *x509.Certificate, SubCAKey *rsa.PrivateKey, commonName string) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	var DeviceTemplate = x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: commonName},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(10 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}

	DeviceCert, DevicePEM := genCert(&DeviceTemplate, SubCACert, &priv.PublicKey, SubCAKey)
	return DeviceCert, DevicePEM, priv

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
	var rootKeyPath = flag.String("keyPath", "", "The private key for the root ca")
	var rootCertPath = flag.String("caPath", "", "The root ca cert path")
	var subKeyPath = flag.String("subKeyPath", "", "The sub ca private Key")
	var subCertPath = flag.String("subCaPath", "", "The sub ca cert path")
	var genCA = flag.Bool("genCA", false, "Generate a new CA")
	var genSubCA = flag.Bool("genSubCA", false, "Generate a new SUB CA")
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

	var SubCACert *x509.Certificate
	var SubCACertPEM []byte
	var SubCAKey *rsa.PrivateKey

	if *genSubCA && ((rootCertPath != nil && rootKeyPath != nil) || (rootCert != nil && rootKey != nil)) {
		var err error
		if rootCert == nil || rootKey == nil {
			if rootCert, rootKey, err = ParsePEMFiles(*rootCertPath, *rootKeyPath); err != nil {
				panic(err)
			}
		}
		SubCACert, SubCACertPEM, SubCAKey = GenSubCA(rootCert, rootKey)
		SubCAPrivKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(SubCAKey)})
		ioutil.WriteFile("subCA.key", SubCAPrivKey, 0644)
		ioutil.WriteFile("subCA.crt", SubCACertPEM, 0644)
		fmt.Println("SubCACert\n", string(SubCACertPEM))
		fmt.Println(string(SubCAPrivKey))
	}
	//verifySubCA(rootCert, SubCACert)

	if *genDeviceCert && ((subCertPath != nil && subKeyPath != nil) || (SubCACert != nil && SubCAKey != nil)) {
		if SubCACert == nil || SubCAKey == nil {
			var err error
			if SubCACert, SubCAKey, err = ParsePEMFiles(*subCertPath, *subKeyPath); err != nil {
				panic(err)
			}
		}
		_, DevicePEM, DeviceKey := GenDeviceCert(SubCACert, SubCAKey, *commonName)
		deviceKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(DeviceKey)})
		ioutil.WriteFile("device-"+*commonName+".key", deviceKey, 0644)
		ioutil.WriteFile("device-"+*commonName+".crt", DevicePEM, 0644)
		fmt.Println(string(deviceKey))
		fmt.Println("DevicePEM\n", string(DevicePEM))
	}
	//verifyLow(rootCert, SubCACert, DeviceCert)
}

func verifySubCA(root, SubCA *x509.Certificate) {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := SubCA.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	fmt.Println("SubCA verified")
}
