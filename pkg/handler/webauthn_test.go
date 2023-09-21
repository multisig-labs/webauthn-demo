package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/multisig-labs/webauthn-demo/pkg/secp256r1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ccr1 = `
		{
			"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
			"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
			"type":"public-key",
			"authenticatorAttachment":"platform",
			"clientExtensionResults":{
				"appid":true
			},
			"response":{
				"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
				"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
				"transports":["usb","nfc","fake"]
			}
		}
	`

// Chrome
var ccrChrome = `
	{
    "id": "4QNPN4id8ZLyUsB5pFwMy-Z3kVTk9WM8AKTpjZaNGvA",
    "rawId": "4QNPN4id8ZLyUsB5pFwMy-Z3kVTk9WM8AKTpjZaNGvA",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIOEDTzeInfGS8lLAeaRcDMvmd5FU5PVjPACk6Y2WjRrwpQECAyYgASFYIGg3EQTh_cXaITybqU0rXXwR5T8PSm8TVDoGLROqwvgFIlgg7FQjrh-55kaDPsdu4wlL40hRJtuJeac81Fb8Am-UM0M",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
        "transports": [
            "internal"
        ],
        "publicKeyAlgorithm": -7,
        "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaDcRBOH9xdohPJupTStdfBHlPw9KbxNUOgYtE6rC-AXsVCOuH7nmRoM-x27jCUvjSFEm24l5pzzUVvwCb5QzQw",
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIOEDTzeInfGS8lLAeaRcDMvmd5FU5PVjPACk6Y2WjRrwpQECAyYgASFYIGg3EQTh_cXaITybqU0rXXwR5T8PSm8TVDoGLROqwvgFIlgg7FQjrh-55kaDPsdu4wlL40hRJtuJeac81Fb8Am-UM0M"
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "authenticatorAttachment": "platform"
	}
	`

// Safari
var ccrSafari = `
		{
			"id": "S3bo0W9IE07okGPT7g03RK8wIW0",
			"rawId": "S3bo0W9IE07okGPT7g03RK8wIW0",
			"response": {
					"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEt26NFvSBNO6JBj0-4NN0SvMCFtpQECAyYgASFYIPCYipOphSkYGtySztVU-9CK6dd4wB02DOZaZFT1bFerIlggPpMU6URsHluEBK0u6Agv2gzGzgqYLVROt50Lmxe2AzQ",
					"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJ9",
					"transports": [
							"internal",
							"hybrid"
					],
					"publicKeyAlgorithm": -7,
					"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8JiKk6mFKRga3JLO1VT70Irp13jAHTYM5lpkVPVsV6s-kxTpRGweW4QErS7oCC_aDMbOCpgtVE63nQubF7YDNA",
					"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEt26NFvSBNO6JBj0-4NN0SvMCFtpQECAyYgASFYIPCYipOphSkYGtySztVU-9CK6dd4wB02DOZaZFT1bFerIlggPpMU6URsHluEBK0u6Agv2gzGzgqYLVROt50Lmxe2AzQ"
			},
			"type": "public-key",
			"clientExtensionResults": {
					"credProps": {
							"rk": true
					}
			},
			"authenticatorAttachment": "platform"
		}
	`

// pubkey base64url MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Hp3RUoRn9XOoJ5ME3Psye4NiMgek8DqeksPtNSKM8MDhpX10nmMqVUZEILYC12mHJUpHEyLGv8o2C3sM_v2Jw
var v1 = `
{
  "pubKey":"0x3059301306072a8648ce3d020106082a8648ce3d03010703420004d07a77454a119fd5cea09e4c1373ecc9ee0d88c81e93c0ea7a4b0fb4d48a33c3038695f5d2798ca955191082d80b5da61c95291c4c8b1aff28d82dec33fbf627",
  "msgHash": "0x698ffda75a3100206571fab033f78b76d9ca8db2ea38fc0579b86619ee98ee0e",
  "msg":"GoGoPoolFTW",
  "sig":"0x3045022100e7715d2266894b8866a24f5d407663a63bbf87d8e9c96bbff40c3ff73ca7d31802202d82c2d958225764147076db76bcb120ef4a4b70515b26208c80560d877b0ede"
}
`

var sigv1 = `
{
    "type": "public-key",
    "id": "LykWH5emxDJ8J2qDPnwu67zAdGh_EfjIuXK1T_XlQ10",
    "rawId": "LykWH5emxDJ8J2qDPnwu67zAdGh/EfjIuXK1T/XlQ10=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYVlfOXAxb3hBQ0JsY2Zxd01fZUxkdG5LamJMcU9Qd0ZlYmhtR2U2WTdnNCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==",
        "signature": "MEYCIQCgFYbnq5NNItPDk7YtVsNxyLILyXANE9eCCP/pft/9pQIhAKLfhK2bmHXWX3L86prsANhBC5XVTZ9VVutT4+UJwTF8",
        "userHandle": "TmVv"
    },
    "clientExtensionResults": {}
}
`

func TestSig1(t *testing.T) {
	body := io.NopCloser(bytes.NewReader([]byte(sigv1)))
	car := &protocol.CredentialAssertionResponse{}

	pcr, err := protocol.ParseCredentialRequestResponseBody(body)
	require.NoError(t, err)
	spew.Dump(pcr)
}

type Data struct {
	Response struct {
		PublicKey protocol.URLEncodedBase64 `json:"publicKey"`
	} `json:"response"`
}

func TestV1(t *testing.T) {
	body := VerifyBody{}
	err := json.Unmarshal([]byte(v1), &body)
	require.NoError(t, err)
	publicKey, msgHash, signature, err := body.ToBytes()
	require.NoError(t, err)
	pk, err := x509.ParsePKIXPublicKey(publicKey)
	require.NoError(t, err)
	epk, ok := pk.(*ecdsa.PublicKey)
	require.True(t, ok)
	ok = secp256r1.VerifySignature(epk, msgHash, signature)
	require.True(t, ok, "Failed to verify sig")
}

// Test that we get the same key from 2 different unmarshal techniques
func TestCCRUnmarshal(t *testing.T) {
	// Slimmed down technique
	ccr := Data{}
	err := json.Unmarshal([]byte(ccrChrome), &ccr)
	require.NoError(t, err)
	pk, err := x509.ParsePKIXPublicKey(ccr.Response.PublicKey)
	require.NoError(t, err)
	epk, ok := pk.(*ecdsa.PublicKey)
	require.NoError(t, err)
	require.True(t, ok)

	// Now use the webauthn code
	ccr2 := protocol.CredentialCreationResponse{}
	err = json.Unmarshal([]byte(ccrChrome), &ccr2)
	require.NoError(t, err)
	ar, err := ccr2.AttestationResponse.Parse()
	require.NoError(t, err)
	pk2, err := webauthncose.ParsePublicKey(ar.AttestationObject.AuthData.AttData.CredentialPublicKey)
	require.NoError(t, err)
	pk2e, ok := pk2.(webauthncose.EC2PublicKeyData)
	require.True(t, ok)

	epk2 := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(pk2e.XCoord),
		Y:     big.NewInt(0).SetBytes(pk2e.YCoord),
	}

	require.True(t, epk.Equal(epk2))
}

func TestCCR(t *testing.T) {
	ccr := protocol.CredentialCreationResponse{}
	err := json.Unmarshal([]byte(ccrChrome), &ccr)
	require.NoError(t, err)
	ar, err := ccr.AttestationResponse.Parse()
	require.NoError(t, err)
	// spew.Dump(ar)
	pubKey, err := webauthncose.ParsePublicKey(ar.AttestationObject.AuthData.AttData.CredentialPublicKey)
	require.NoError(t, err)
	e, ok := pubKey.(webauthncose.EC2PublicKeyData)
	require.True(t, ok)

	credPKInfo := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(e.XCoord),
		Y:     big.NewInt(0).SetBytes(e.YCoord),
	}

	spew.Dump(e)
	spew.Dump(credPKInfo)

	// valid, err = e.Verify(signatureData, sig)
	// pub, err := x509.ParsePKIXPublicKey
	t.Fatal()
}

func TestP256SignatureVerification(t *testing.T) {
	// Private/public key pair was generated with the following:
	//
	// $ openssl ecparam -genkey -name secp256r1 -noout -out private_key.pem
	// $ openssl ec -in private_key.pem -noout -text
	// Private-Key: (256 bit)
	// priv:
	// 	48:7f:36:1d:df:d7:34:40:e7:07:f4:da:a6:77:5b:
	// 	37:68:59:e8:a3:c9:f2:9b:3b:b6:94:a1:29:27:c0:
	// 	21:3c
	// pub:
	// 	04:f7:39:f8:c7:7b:32:f4:d5:f1:32:65:86:1f:eb:
	// 	d7:6e:7a:9c:61:a1:14:0d:29:6b:8c:16:30:25:08:
	// 	87:03:16:c2:49:70:ad:78:11:cc:d9:da:7f:1b:88:
	// 	f2:02:be:ba:c7:70:66:3e:f5:8b:a6:83:46:18:6d:
	// 	d7:78:20:0d:d4
	// ASN1 OID: prime256v1
	// NIST CURVE: P-256
	// ----.
	pubX, err := hex.DecodeString("f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316")
	assert.Nil(t, err)
	pubY, err := hex.DecodeString("c24970ad7811ccd9da7f1b88f202bebac770663ef58ba68346186dd778200dd4")
	assert.Nil(t, err)

	key := webauthncose.EC2PublicKeyData{
		// These constants are from https://datatracker.ietf.org/doc/rfc9053/
		// (see "ECDSA" and "Elliptic Curve Keys").
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   2,  // EC.
			Algorithm: -7, // "ES256".
		},
		Curve:  1, // P-256.
		XCoord: pubX,
		YCoord: pubY,
	}

	data := []byte("webauthnFTW")

	// Valid signature obtained with:
	// $ echo -n 'webauthnFTW' | openssl dgst -sha256 -sign private_key.pem | xxd -ps | tr -d '\n'.
	validSig, err := hex.DecodeString("3045022053584980793ee4ec01d583f303604c4f85a7e87df3fe9551962c5ab69a5ce27b022100c801fd6186ca4681e87fbbb97c5cb659f039473995a75a9a9dffea2708d6f8fb")
	assert.Nil(t, err)

	// Happy path, verification should succeed.
	ok, err := webauthncose.VerifySignature(key, data, validSig)
	assert.True(t, ok, "invalid EC signature")
	assert.Nil(t, err, "error verifying EC signature")

	// Verification against BAD data should fail.
	ok, err = webauthncose.VerifySignature(key, []byte("webauthnFTL"), validSig)
	assert.Nil(t, err, "error verifying EC signature")
	assert.False(t, ok, "verification against bad data is successful!")

	// Now try with this known good test data but using different packages

	// echo -n 'webauthnFTW' | openssl dgst -sha256
	h, _ := hex.DecodeString("bd1b0a3a41933220c3dd00c29e6bd613fa6749c01fc376ffbcff2459ec19c41d")

	type ECDSASignature struct {
		R, S *big.Int
	}
	esig := &ECDSASignature{}
	_, err = asn1.Unmarshal(validSig, esig)
	assert.NoError(t, err)
	pk2 := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(key.XCoord),
		Y:     big.NewInt(0).SetBytes(key.YCoord),
	}

	ok = ecdsa.Verify(pk2, h, esig.R, esig.S)
	assert.True(t, ok, "invalid EC signature")

}
