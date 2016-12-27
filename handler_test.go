package auth

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

var (
	publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAyLOtVh8qXjdwfjZZYwkE
gg1yoSzmpKKpmzYW745lBGtPH87FspHVHeqjmgFnBsARsD7CHzYyQTho7oLrAEbu
F7tKdGRK25wJIenPKKuL+UVwZNeJVEXSiMNmX3Y4IqRteqRIjhw3DmXYHEWvBc2J
Vy8lWtyK+o6o8jlO0aRTTT2+dETpyqKqNJyHVNz2u6XVtm7jqyLU7tAqW+qpr5zS
oNmuUAyz6JDCRnlWvwp1qzuS1LV32HK9yfq8TGriDVPyPRpFRmiRGWGIrIKrmm4s
ImpoLfuVBITjeh8V3Ee0OCDmTLgYlTHAmCLFJxaW5Y8b4cTt5pbT7R1iu77RKJo3
fwIBIw==
-----END PUBLIC KEY-----`
)

func TestSuccessFullRequestValidation(t *testing.T) {
	auth, _ := NewAuth("test_user", key, "rsa-sha512")

	timestamp := time.Now().Format(http.TimeFormat)
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("Date", timestamp)

	authHeader, err := CreateAuthorizationHeader(req, []string{"date"}, auth)
	if err != nil {
		t.Error("Failed to sign request")
		t.FailNow()
	}
	req.Header.Set("Authorization", authHeader)

	err = ValidateRequest(req, func(keyId string) (crypto.PublicKey, error) {
		block, _ := pem.Decode([]byte(publicKey))
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse public key: %+v", err)
			return nil, err
		}
		return pubKey.(crypto.PublicKey), nil
	})

	if err != nil {
		t.Error("Test was unable to validate request.", err)
	}
}

func TestInvalidAuthHeader(t *testing.T) {
	header := "Basic test123"
	timestamp := time.Now().Format(http.TimeFormat)
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("Authorization", header)
	req.Header.Set("Date", timestamp)

	err := ValidateRequest(req, func(keyId string) (crypto.PublicKey, error) {
		block, _ := pem.Decode([]byte(publicKey))
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse public key: %+v", err)
			return nil, err
		}
		return pubKey.(crypto.PublicKey), nil
	})

	if err != InvalidHeaderValue {
		t.Error("Tried to validate with invalid authorization header, but got different error: %+v", err)
	}
}

func TestParsingHeaderValue(t *testing.T) {
	header := `Signature keyId="/test_user/keys/test_key",algorithm="rsa-sha256",signature="yK0J17CQ04ZvMsFLoH163Sjyg8tE4BoIeCsmKWLQKN3BYgSpR0XyqrecheQ2A0o4L99oSumYSKIscBSiH5rqdf4/1zC/FEkYOI2UzcIHYb1MPNzO3g/5X44TppYE+8dxoH99V+Ts8RT3ZurEYjQ8wmK0TnxdirAevSpbypZJaBOFXUZSxx80m5BD4QE/MSGo/eaVdJI/Iw+nardHNvimVCr6pRNycX1I4FdyRR6kgrAl2NkY2yxx/CAY21Ir+dmbG3A1x4GiIE485LLheAL5/toPo7Gh8G5fkrF9dXWVyX0k9AZXqXNWn5AZxc32dKL2enH09j/X86RtwiR1IEuPww=="`
	keyId, algorithmName, headerFields, signature, err := extractAuthData(header)
	if err != nil {
		t.Error("Failed extract auth data", err)
		t.FailNow()
	}
	headerList := strings.Join(headerFields, " ")
	if headerList != "date" {
		t.Error("Failed to extract correct headerList", headerList)
	}

	if keyId != "/test_user/keys/test_key" {
		t.Error("Failed to extract correct keyId", keyId)
	}

	if algorithmName != "rsa-sha256" {
		t.Error("Failed to extract correct algorithm name", algorithmName)
	}

	if signature != `yK0J17CQ04ZvMsFLoH163Sjyg8tE4BoIeCsmKWLQKN3BYgSpR0XyqrecheQ2A0o4L99oSumYSKIscBSiH5rqdf4/1zC/FEkYOI2UzcIHYb1MPNzO3g/5X44TppYE+8dxoH99V+Ts8RT3ZurEYjQ8wmK0TnxdirAevSpbypZJaBOFXUZSxx80m5BD4QE/MSGo/eaVdJI/Iw+nardHNvimVCr6pRNycX1I4FdyRR6kgrAl2NkY2yxx/CAY21Ir+dmbG3A1x4GiIE485LLheAL5/toPo7Gh8G5fkrF9dXWVyX0k9AZXqXNWn5AZxc32dKL2enH09j/X86RtwiR1IEuPww==` {
		t.Error("Failed to extract correct signature", signature)
	}
}

func TestValidateDateHeaderDateTooOld(t *testing.T) {
	timestamp := time.Now().Add(time.Minute * -6)
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("Date", timestamp.Format(http.TimeFormat))

	err := validatDateHeader(req)
	if err != RequestTimeInvalid {
		t.Error("Validation of Date header should have failed because date is too old", err)
	}
}

func TestMissingDateHeader(t *testing.T) {
	req := &http.Request{}
	req.Header = make(http.Header)
	err := validatDateHeader(req)
	if err != MissingDateHeader {
		t.Error("Validation of Date header should have failed because of missing date header", err)
	}
}

func TestInvalidDateHeader(t *testing.T) {
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("Date", "23.12.2016 16:23")

	err := validatDateHeader(req)
	if err == nil {
		t.Error("Validation of Date header should have failed because Date header is not correctly formatted", err)
	}
}

func TestSuccessfullDateHeaderValidation(t *testing.T) {
	timestamp := time.Now().Format(http.TimeFormat)
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("Date", timestamp)

	err := validatDateHeader(req)
	if err != nil {
		t.Error("Validation of Date header should have succeeded", err)
	}
}

func TestAuthHeaderWithoutHeadersList(t *testing.T) {
	keyId, algorithmName, headerList, signature, err := extractAuthData(`Signature keyId="rsa-key-1",algorithm="rsa-sha256",signature="Base64-String"`)
	if err != nil {
		t.Error("Failed to extract header data: ", err)
		t.FailNow()
	}
	if keyId != "rsa-key-1" {
		t.Error("Extracted wrong keyId", keyId)
	}
	if algorithmName != "rsa-sha256" {
		t.Error("Extracted wrong algorithm name", algorithmName)
	}
	if signature != "Base64-String" {
		t.Error("Extracted wrong signature string")
	}
	if len(headerList) == 0 {
		t.Error("Received no header list although date needs to be always there")
	}
}

func TestAuthHeaderWithHeadersList(t *testing.T) {
	keyId, algorithmName, headerList, signature, err := extractAuthData(`Signature keyId="test_user",algorithm="rsa-sha512",headers="date",signature="KR+S1xfSH8nZiORiPeBJKVnB38XDWlXAe+lhyA06fJ+cU4wTY0fvHAi4xpnbKtdtLsLaBg/b1HX/Wno2oJqBRbxYTj7FHSshOTszXxIyX1Bcq393hlcjy6zYUGSl60T14+dytEyUgGj9qySH89nPoBVJSlUfTL2RfsFmWgEsnFSiQg6/RzcozmERBWn0VL/F2Gfc+zc78lmhr/2s+NK1pvF7xQGy+AyD7ftH10OjrpfrxeTi2edPkfW5PRntgi+Jyfe7OJoaDZaAQSKsg+Ql3yVERVnk/36MHEkdLnvSbOiDNZ2g0/MOyjBLV58OIC6hKXdL9KnUX8u9UGTBwEzxrA=="`)
	if err != nil {
		t.Error("Failed to extract header data: ", err)
		t.FailNow()
	}
	if keyId != "test_user" {
		t.Error("Extracted wrong keyId", keyId)
	}
	if algorithmName != "rsa-sha512" {
		t.Error("Extracted wrong algorithm name", algorithmName)
	}
	if signature != "KR+S1xfSH8nZiORiPeBJKVnB38XDWlXAe+lhyA06fJ+cU4wTY0fvHAi4xpnbKtdtLsLaBg/b1HX/Wno2oJqBRbxYTj7FHSshOTszXxIyX1Bcq393hlcjy6zYUGSl60T14+dytEyUgGj9qySH89nPoBVJSlUfTL2RfsFmWgEsnFSiQg6/RzcozmERBWn0VL/F2Gfc+zc78lmhr/2s+NK1pvF7xQGy+AyD7ftH10OjrpfrxeTi2edPkfW5PRntgi+Jyfe7OJoaDZaAQSKsg+Ql3yVERVnk/36MHEkdLnvSbOiDNZ2g0/MOyjBLV58OIC6hKXdL9KnUX8u9UGTBwEzxrA==" {
		t.Error("Extracted wrong signature string")
	}
	if len(headerList) == 0 {
		t.Error("Received no header list although date needs to be always there")
	}

	if headerList[0] != "date" {
		t.Error("Date should be in the headers to sign")
	}
}
