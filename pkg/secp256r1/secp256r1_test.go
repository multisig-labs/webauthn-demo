package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pubKey    string = "03b434054a968479e6d1adb7b6185d1373c5b8f9cdd0813028327e6a342d702df6"
	dataHash  string = "989a647219cb0c3de61ec045ea197b8c48e8e40bc3fda8b93033b96b109a222a"
	signature string = "3045022074bcdc20e53b9342b8dad74aa65dfc8c0b80c3963f596440452316c762fa4b81022100f693c4b11ca20c3cffe96a4d0f404fcfeaf4b954d3d4dd162fe156381de654a6"
)

func TestVerifySignatureR1(t *testing.T) {
	pkh, _ := hex.DecodeString(pubKey)
	dhh, _ := hex.DecodeString(dataHash)
	sh, _ := hex.DecodeString(signature)

	ok := VerifySignature(pkh, dhh, sh)
	assert.True(t, ok)

	ok = VerifySignature(pkh, sh, dhh)
	assert.False(t, ok)
}

func TestGeneratePrivateKey(t *testing.T) {
	pub, pk, err := GenerateKey()
	require.NoError(t, err)
	t.Logf("%x", pub)
	t.Logf("%x", pk)
	t.Logf("%s", pk.ToHex())
	t.Logf("Addr: %s", Address("r1", pub))
	t.Fatal()
}

func TestECDSAPublicKeyFromRaw(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "GenerateKey failed")

	pubKey := privKey.PublicKey

	// Marshal key into the raw Apple format.
	rawAppleKey := make([]byte, 1+32+32)
	rawAppleKey[0] = 0x04
	pubKey.X.FillBytes(rawAppleKey[1:33])
	pubKey.Y.FillBytes(rawAppleKey[33:])

	got, err := ECDSAPublicKeyFromRaw(rawAppleKey)
	require.NoError(t, err, "ECDSAPublicKeyFromRaw failed")
	assert.Equal(t, pubKey, *got, "ECDSAPublicKeyFromRaw mismatch")
}
