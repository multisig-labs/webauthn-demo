package secp256r1

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ava-labs/avalanchego/utils/formatting/address"
)

const (
	PublicKeyLen  = 33
	PrivateKeyLen = 32
	SignatureLen  = 72
)

type (
	PublicKey  [PublicKeyLen]byte
	PrivateKey [PrivateKeyLen]byte
	Signature  [SignatureLen]byte
)

var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrIncorrectHrp      = errors.New("incorrect hrp")
	ErrInvalidSignature  = errors.New("invalid signature")
)

var (
	EmptyPublicKey  = PublicKey{}
	EmptyPrivateKey = PrivateKey{}
	EmptySignature  = Signature{}
)

// TODO?
// signature size can vary from 70 to 72 bytes, so we are left-trimming
// signature = common.TrimLeftZeroes(signature)

func VerifySignature(pubKey *ecdsa.PublicKey, dataHashByte, signatureByte []byte) bool {
	// pubKey := newPubKey(pubKeyByte)
	if pubKey.X == nil || pubKey.Y == nil {
		return false
	}
	if len(dataHashByte) != 32 {
		panic("not a hash")
	}

	// type ECDSASignature struct {
	// 	R, S *big.Int
	// }
	// esig := &ECDSASignature{}

	// if _, err := asn1.Unmarshal(signatureByte, esig); err != nil {
	// 	return false
	// }

	// ok := ecdsa.Verify(pubKey, dataHashByte, esig.R, esig.S)
	// return ok

	return ecdsa.VerifyASN1(pubKey, dataHashByte, signatureByte)
}

func newPubKey(pk []byte) *ecdsa.PublicKey {
	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X, pubKey.Y = elliptic.UnmarshalCompressed(pubKey.Curve, pk)

	return pubKey
}

// Address returns a Bech32 address from hrp and p.
// This function uses avalanchego's FormatBech32 function.
func Address(hrp string, p PublicKey) string {
	addrString, _ := address.FormatBech32(hrp, p[:])
	return addrString
}

// ParseAddress parses a Bech32 encoded address string and extracts
// its public key. If there is an error reading the address or the hrp
// value is not valid, ParseAddress returns an EmptyPublicKey and error.
func ParseAddress(hrp, saddr string) (PublicKey, error) {
	phrp, pk, err := address.ParseBech32(saddr)
	if err != nil {
		return EmptyPublicKey, err
	}
	if phrp != hrp {
		return EmptyPublicKey, ErrIncorrectHrp
	}
	// The parsed public key may be greater than [PublicKeyLen] because the
	// underlying Bech32 implementation requires bytes to each encode 5 bits
	// instead of 8 (and we must pad the input to ensure we fill all bytes):
	// https://github.com/btcsuite/btcd/blob/902f797b0c4b3af3f7196d2f5d2343931d1b2bdf/btcutil/bech32/bech32.go#L325-L331
	if len(pk) < PublicKeyLen {
		return EmptyPublicKey, ErrInvalidPublicKey
	}
	return PublicKey(pk[:PublicKeyLen]), nil
}

func GenerateKey() (PublicKey, PrivateKey, error) {
	curve := ecdh.P256()
	pk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return EmptyPublicKey, EmptyPrivateKey, err
	}
	return PublicKey(pk.PublicKey().Bytes()), PrivateKey(pk.Bytes()), nil
}

// ToHex converts a PrivateKey to a hex string.
func (p PrivateKey) ToHex() string {
	return hex.EncodeToString(p[:])
}

func (p PrivateKey) Bytes() []byte {
	return p[:]
}

// ToHex converts a PublicKey to a hex string.
func (p PublicKey) ToHex() string {
	return hex.EncodeToString(p[:])
}

func (p PublicKey) Bytes() []byte {
	return p[:]
}

// ECDSAPublicKeyFromRaw reads an ECDSA public key from a raw Apple public key,
// as returned by SecKeyCopyExternalRepresentation.
func ECDSAPublicKeyFromRaw(pubKeyRaw []byte) (*ecdsa.PublicKey, error) {
	// Verify key length to avoid a potential panic below.
	// 3 is the smallest number that clears it, but in practice 65 is the more
	// common length.
	// Apple's docs make no guarantees, hence no assumptions are made here.
	switch l := len(pubKeyRaw); {
	case l < 3:
		return nil, fmt.Errorf("public key representation too small (%v bytes)", l)
	case l%2 != 1: // 0x4+keyLen+keyLen is always odd, see explanation below.
		return nil, fmt.Errorf("public key representation has unexpected length (%v bytes)", l)
	case pubKeyRaw[0] != 0x04: // See explanation below.
		return nil, fmt.Errorf("public key representation starts with unexpected byte (%#x vs 0x4)", pubKeyRaw[0])
	}

	// "For an elliptic curve public key, the format follows the ANSI X9.63
	// standard using a byte string of 04 || X || Y. (...) All of these
	// representations use constant size integers, including leading zeros as
	// needed."
	// https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation?language=objc
	pubKeyRaw = pubKeyRaw[1:] // skip 0x4
	l := len(pubKeyRaw) / 2
	x := pubKeyRaw[:l]
	y := pubKeyRaw[l:]

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     (&big.Int{}).SetBytes(x),
		Y:     (&big.Int{}).SetBytes(y),
	}, nil
}
