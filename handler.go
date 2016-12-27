package httpsignature

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	httpSignatureExpression = `^Signature keyId="([A-Za-z0-9_\-\.:/]+)",algorithm="([a-z0-9\-]+)",(headers="([a-z0-9\-]+)",)?signature="(.*)"$`
)

var (
	InvalidHeaderValue   = errors.New("Invalid Header value")
	MissingDateHeader    = errors.New("Missing date header")
	RequestTimeInvalid   = errors.New("Request time is either too young or too old")
	InvalidPublicKeyType = errors.New("Invalid public key type")

	HttpSignatureRegex = regexp.MustCompile(httpSignatureExpression)

	MaxClockSkew = time.Minute * 5
)

type KeyLookupFunc func(keyId string) (crypto.PublicKey, error)

func KeyFileLookUp(keyDir string) KeyLookupFunc {
	return func(keyId string) (crypto.PublicKey, error) {
		keyFilename := keyId + ".pem"
		keyPath := path.Join(keyDir, keyFilename)
		fileBytes, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(fileBytes))
		x509pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		return x509pubKey.(crypto.PublicKey), err
	}
}

func CheckAuthorization(next http.HandlerFunc, keyLookup KeyLookupFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := ValidateRequest(r, keyLookup); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func ValidateRequest(r *http.Request, keyLookup KeyLookupFunc) error {
	if err := validatDateHeader(r); err != nil {
		return err
	}

	keyId, algorithmName, headerFields, signature, err := extractAuthData(r.Header.Get("Authorization"))
	if err != nil {
		return err
	}

	key, err := keyLookup(keyId)
	if err != nil {
		return err
	}

	signed, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	hashFunc := getHashFunction(algorithmName)
	hashed, err := generateDigest(r, hashFunc, headerFields)
	if err != nil {
		return err
	}

	rsaPubKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return InvalidPublicKeyType
	}
	return rsa.VerifyPKCS1v15(rsaPubKey, hashFunc, hashed, signed)
}

func validatDateHeader(r *http.Request) error {
	dateHeaderValue := r.Header.Get("Date")
	if dateHeaderValue == "" {
		return MissingDateHeader
	}

	timestamp, err := time.ParseInLocation(http.TimeFormat, dateHeaderValue, time.Local)
	if err != nil {
		return err
	}

	expiryTime := timestamp.Add(MaxClockSkew)
	notBefore := timestamp.Add(MaxClockSkew * -1)
	now := time.Now()
	if now.After(expiryTime) || now.Before(notBefore) {
		return RequestTimeInvalid
	}
	return nil
}

func extractAuthData(headerValue string) (string, string, []string, string, error) {
	matches := HttpSignatureRegex.FindAllStringSubmatch(headerValue, -1)
	if matches == nil {
		return "", "", []string{}, "", InvalidHeaderValue
	}
	keyId := matches[0][1]
	algorithmName := matches[0][2]
	headerList := matches[0][4]
	if headerList == "" {
		headerList = "date"
	}
	if !strings.Contains(headerList, "date") {
		headerList = headerList + " date"
	}
	headerFields := strings.Fields(headerList)
	signature := matches[0][5]

	return keyId, algorithmName, headerFields, signature, nil
}
