//
// gosign - Go HTTP signing library for the Joyent Public Cloud and Joyent Manta
//
//
// Copyright (c) 2013 Joyent Inc.
//
// Written by Daniele Stroppa <daniele.stroppa@joyent.com>
//

package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
)

const (
	// Authorization Headers
	HttpSignature = `Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"`
)

type Auth struct {
	KeyId      string
	PrivateKey PrivateKey
	Algorithm  string
}

type PrivateKey struct {
	key *rsa.PrivateKey
}

// NewAuth creates a new Auth.
func NewAuth(keyId, privateKey, algorithm string) (*Auth, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, fmt.Errorf("invalid private key data: %s", privateKey)
	}
	rsakey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while parsing the key: %s", err)
	}
	return &Auth{keyId, PrivateKey{rsakey}, algorithm}, nil
}

// The CreateAuthorizationHeader returns the Authorization header for the give request.
func CreateAuthorizationHeader(r *http.Request, headerFields []string, auth *Auth) (string, error) {
	if len(headerFields) == 0 {
		headerFields = append(headerFields, "date")
	}
	hashFunc := getHashFunction(auth.Algorithm)

	digest, err := generateDigest(r, hashFunc, headerFields)
	if err != nil {
		return "", nil
	}

	signed, err := rsa.SignPKCS1v15(rand.Reader, auth.PrivateKey.key, hashFunc, digest)

	signature := base64.StdEncoding.EncodeToString(signed)
	headerList := strings.Join(headerFields, " ")
	return fmt.Sprintf(HttpSignature, auth.KeyId, auth.Algorithm, headerList, signature), nil
}

func generateDigest(r *http.Request, hashFunc crypto.Hash, headerFields []string) ([]byte, error) {
	hash := hashFunc.New()
	for i, headerField := range headerFields {
		if headerField == "request-line" {
			// rebuild the original request-line
			hash.Write([]byte(r.Method + " " + r.RequestURI + " " + r.Proto))
		} else {
			hash.Write([]byte(headerField + ": " + r.Header.Get(headerField)))
		}
		if i < len(headerFields)-1 {
			hash.Write([]byte("\n"))
		}
	}
	return hash.Sum(nil), nil
}

// Helper method to get the Hash function based on the algorithm
func getHashFunction(algorithm string) (hashFunc crypto.Hash) {
	switch strings.ToLower(algorithm) {
	case "rsa-sha1":
		hashFunc = crypto.SHA1
	case "rsa-sha224", "rsa-sha256":
		hashFunc = crypto.SHA256
	case "rsa-sha384", "rsa-sha512":
		hashFunc = crypto.SHA512
	default:
		hashFunc = crypto.SHA256
	}
	return
}
