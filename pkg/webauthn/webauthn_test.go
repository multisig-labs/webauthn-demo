package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecover(t *testing.T) {
}

func TestPublicKeyFormatInvestigation(t *testing.T) {
	// pubkey as recvd from webauthn `navigator.credentials.create`
	raw := `{"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv4CxUa2BY8HbnGVcQ7nLctZZjSxNmYfQf7zSnH3tauCOY11yPNuo1Mqixlo73cDFwMwGtWEy4ZJOzs4YpKONAg"}`
	w := Webauthn{}

	err := json.NewDecoder(strings.NewReader(raw)).Decode(&w)
	require.NoError(t, err)
	// 3059301306072a8648ce3d020106082a8648ce3d03010703420004bf80b151ad8163c1db9c655c43b9cb72d6598d2c4d9987d07fbcd29c7ded6ae08e635d723cdba8d4caa2c65a3bddc0c5c0cc06b56132e1924ecece18a4a38d02
	t.Logf("raw bytes ANS.1 DER: %x", []byte(w.PublicKey))
	// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv4CxUa2BY8HbnGVcQ7nLctZZjSxNmYfQf7zSnH3tauCOY11yPNuo1Mqixlo73cDFwMwGtWEy4ZJOzs4YpKONAg
	t.Logf("raw bytes ANS.1 DER: %s", w.PublicKey)

	pk1, err := x509.ParsePKIXPublicKey(w.PublicKey)
	require.NoError(t, err)

	epk, ok := pk1.(*ecdsa.PublicKey)
	require.True(t, ok)

	pk3 := append(epk.X.Bytes(), epk.Y.Bytes()...)
	// bf80b151ad8163c1db9c655c43b9cb72d6598d2c4d9987d07fbcd29c7ded6ae08e635d723cdba8d4caa2c65a3bddc0c5c0cc06b56132e1924ecece18a4a38d02
	t.Logf("append(X,Y): %x", pk3)

	pkecdh, err := epk.ECDH()
	require.NoError(t, err)
	// 04bf80b151ad8163c1db9c655c43b9cb72d6598d2c4d9987d07fbcd29c7ded6ae08e635d723cdba8d4caa2c65a3bddc0c5c0cc06b56132e1924ecece18a4a38d02
	t.Logf("ECDH().Bytes(): %x", pkecdh.Bytes())

	// t.Fatal()
}

func TestAddressFormat(t *testing.T) {
	// pubkey as recvd from webauthn `navigator.credentials.create`
	raw := `{"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv4CxUa2BY8HbnGVcQ7nLctZZjSxNmYfQf7zSnH3tauCOY11yPNuo1Mqixlo73cDFwMwGtWEy4ZJOzs4YpKONAg"}`
	w := Webauthn{}

	err := json.NewDecoder(strings.NewReader(raw)).Decode(&w)
	require.NoError(t, err)
	addr, err := w.Address()
	require.NoError(t, err)
	require.Equal(t, "1Hv5rftTyqKUG2g7X1VHDJcbJNtBPnfKS4", addr)
	t.Log(addr)
	// t.Fatal()
}

// Chrome CredentialCreationResponse
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
var goodSigChrome = `
{
  "walletId": "brlyjlwMCj9jzB-a8cAOFb0iQ4vzYa-H5RcCCKgk2u0",
  "walletName": "3334tt34",
  "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENWJYusCH6_YZmi_x-f0XpsmcXaqVTNY_rR2LOtXNfWW1ZsXlLvvhG1ojdgZ7eiylaSXnZUC_qE_nCfLIsoxBjA",
  "serializedTx": "eyJiIjoicSIsInoiOjF9",
  "webauthnResponse": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTGdITnRsZTg4STJfTWljeUl4WmJqTGVpRkZuZzRXTEo0TllqUUZfbVpucyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAACQ",
    "signature": "MEYCIQD6HWRZy5sH6ikoBsvPh6MAVnG4YBIg_h-S9Xlj7DP83AIhAMhY-BhN_EfHMdzcYYIUG5a-daCBiGAH3XNxml1drmad",
    "userHandle": "MzMzNHR0MzQ"
  }
}
`

var goodSigSafari = `
{
  "walletId": "4cD5Z041-PipYojK8LYj9NpPM6g",
  "walletName": "test1",
  "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8jnV_DopEtdjMpUjDUO6heT27RHdNt9jSptsWlP8SehY4SfdqMrCKuuAQqgOF_qhoDkmEx-6JKvqwBqp85ba7g",
  "serializedTx": "eyJiIjoicSIsInoiOjF9",
  "webauthnResponse": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTGdITnRsZTg4STJfTWljeUl4WmJqTGVpRkZuZzRXTEo0TllqUUZfbVpucyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJ9",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
    "signature": "MEUCIGfkQ81OcuGjz7GIf5P0fMsfuG1Sdb3Cooo6nI-utrjLAiEA3dp1Q7hONDeMPRZYeLBwOP8KEagr2SlClWxFl1GOdG8",
    "userHandle": "dGVzdDE"
  }
}
`

func TestGoodSigChrome(t *testing.T) {
	w := Webauthn{}
	err := json.Unmarshal([]byte(goodSigChrome), &w)
	require.NoError(t, err)
	ok, err := w.Verify()
	require.NoError(t, err)
	require.True(t, ok, "sig failed to verify")
	addr, err := w.Address()
	require.NoError(t, err)
	require.Equal(t, "1B84hAYd3EaY9zigrU3Rz2WvStKGaK5mNB", addr)
	t.Fatal()
}

func TestBadSigChrome(t *testing.T) {
	w := Webauthn{}
	err := json.Unmarshal([]byte(goodSigChrome), &w)
	require.NoError(t, err)
	w.SerializedTx = protocol.URLEncodedBase64([]byte("tampered"))
	ok, err := w.Verify()
	require.Error(t, err)
	require.False(t, ok, "sig failed to verify")
}

func TestGoodSigSafari(t *testing.T) {
	w := Webauthn{}
	err := json.Unmarshal([]byte(goodSigSafari), &w)
	require.NoError(t, err)
	ok, err := w.Verify()
	require.NoError(t, err)
	require.True(t, ok, "sig failed to verify")
	addr, err := w.Address()
	require.NoError(t, err)
	require.Equal(t, "1LbVkYMNdQ3bjd46yH1qreWUjkyY9XyXmY", addr)
}

// Test that we get the same key from 2 different unmarshal techniques
func TestUnmarshal(t *testing.T) {
	raw := `{"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaDcRBOH9xdohPJupTStdfBHlPw9KbxNUOgYtE6rC-AXsVCOuH7nmRoM-x27jCUvjSFEm24l5pzzUVvwCb5QzQw"}`
	w := Webauthn{}
	err := json.NewDecoder(strings.NewReader(raw)).Decode(&w)
	require.NoError(t, err)

	// Slimmed down technique
	pk, err := x509.ParsePKIXPublicKey(w.PublicKey)
	require.NoError(t, err)
	epk, ok := pk.(*ecdsa.PublicKey)
	require.NoError(t, err)
	require.True(t, ok)

	// Now use the webauthn code
	ccr := protocol.CredentialCreationResponse{}
	err = json.Unmarshal([]byte(ccrChrome), &ccr)
	require.NoError(t, err)
	ar, err := ccr.AttestationResponse.Parse()
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

// func TestEckrRandom(t *testing.T) {
// 	hash := make([]byte, 32)
// 	for i := 0; i < 1000; i++ {
// 		n, err := io.ReadFull(rand.Reader, hash)
// 		if err != nil {
// 			t.Fatalf("error: %v", err)
// 		}
// 		if n != 32 {
// 			t.Fatal("error reading random data")
// 		}
// 		c := elliptic.P256()
// 		priv, err := ecdsa.GenerateKey(c, rand.Reader)
// 		if err != nil {
// 			t.Fatalf("error: %v", err)
// 		}
// 		pub := priv.PublicKey
// 		r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
// 		if err != nil {
// 			t.Fatalf("error: %v", err)
// 		}

// 		///////////////////////////////////////

// 		keys, err := RecoverPublicKeys(c, hash[:], r, s)
// 		if err != nil {
// 			t.Fatalf("error: %v", err)
// 		}

// 		if keys[0].X.Cmp(pub.X) == 0 && keys[0].Y.Cmp(pub.Y) == 0 {
// 			continue
// 		}

// 		if keys[1].X.Cmp(pub.X) == 0 && keys[1].Y.Cmp(pub.Y) == 0 {
// 			continue
// 		}

// 		t.Fatalf("Could not derive keys: iteration:%d", i)
// 	}
// }
