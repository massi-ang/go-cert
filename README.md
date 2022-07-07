# go-cert

A super simple tool that generates a Root CA, a subordinate CA and Device Certificates.

Check the options with:

`./go-cert -help`

## Why

`openssl` is typically used to create certificate and provides multiple options. 
One issue I faced with openssl is the ability to generate really short lived certificates for testing purposes, typically less than 1 day. 

`openssl` allows the creation of specific certificate durations, but to do so, you need to use the `ca` command and in turn that requires a complex `ca.conf` and additional folder and files to be able to generate such certificates.

This tool, based on golang x509 libraries, provides a simpler way to generate such certificates and could be used for testing and demonstration purposes

## How to use

You'll need go 1.15 or above to use this tool. 

Clone the repo and run `go build *.go`.

The code is intended to be an sample that will be modified to suit the user needs. 
It provides some flags that can be used to control the certificate generation and to import existing CAs instead of creating new ones. The certificates and private keys being created are saved to disk and printed on screen.

It allows the creation of:
CA -> SubCA -> Device certificate

For the device certificate it requires a Common Name and creates files using that common name which allow for a repeated use to create multiple certificates.

### Adapt to your need

If you need specific values for the Certificate attributes you simply modify the code - no never ending comman line parameters or complex configuration files.

Open `gocert.go` and look for the variable called `...Template`. There you can add new attributes or modify the values for the existing ones. Full documentation is found here https://pkg.go.dev/crypto/x509?utm_source=gopls#Certificate




