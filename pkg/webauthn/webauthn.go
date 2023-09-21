package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/go-webauthn/webauthn/protocol"
	"golang.org/x/crypto/blake2b"
)

// Front end sends this JSON transaction to us for verification
type Webauthn struct {
	// Must be result of calling `getPublicKey()` on FE
	// Ideally we would just recover this key since we have the signature and the hash it signed.
	// But I couldnt find any Go libs that implement that (yet!)
	PublicKey protocol.URLEncodedBase64 `json:"publicKey" validate:"required"`
	// Canonicalized JSON string, base64URL encoded
	SerializedTx protocol.URLEncodedBase64 `json:"serializedTx" validate:"required"`
	// Webauthn AuthenticatorAssertionResponse (binary fields encoded as base64URL)
	Response struct {
		ClientDataJSON    protocol.URLEncodedBase64 `json:"clientDataJSON" validate:"required"`
		AuthenticatorData protocol.URLEncodedBase64 `json:"authenticatorData" validate:"required"`
		Signature         protocol.URLEncodedBase64 `json:"signature" validate:"required"`
	} `json:"webauthnResponse" validate:"required"`
}

// Verify the signature is valid for the public key and tx provided
func (w Webauthn) Verify() (bool, error) {
	k, err := w.getPublicKey()
	if err != nil {
		return false, fmt.Errorf("error deserializing public key: %w", err)
	}
	if ok := w.verifyChallenge(); !ok {
		return false, fmt.Errorf("tx hash does not match signed challenge")
	}
	h := w.signedDataHash()

	// sig, err := ecdsad.ParseDERSignature(w.Response.Signature)
	// if err != nil {
	// 	return false, err
	// }
	// r := sig.R()
	// rb := (&r).Bytes()
	// s := sig.S()
	// sb := (&s).Bytes()

	// r2 := new(big.Int).SetBytes(rb[:])
	// s2 := new(big.Int).SetBytes(sb[:])
	// z, err := RecoverPublicKeys(elliptic.P256(), h[:], r2, s2)
	// if err != nil {
	// 	return false, err
	// }
	// spew.Dump(z)
	if ok := ecdsa.VerifyASN1(k, h[:], w.Response.Signature); !ok {
		return false, fmt.Errorf("invalid signature")
	}
	return true, nil
}

// Use the PublicKey to make an address format of our own.
//
// Equiv JS code:
//
//	const pubkey = await window.crypto.subtle.importKey(
//	  "spki",
//	  new Uint8Array(publicKeyBuffer),
//	  { name: "ECDSA", namedCurve: "P-256" },
//	  true,
//	  []
//	);
//	const rawBytes = await crypto.subtle.exportKey("raw", pubkey);
func (w Webauthn) Address() (string, error) {
	pk, err := w.getPublicKey()
	if err != nil {
		return "", err
	}

	pkecdh, err := pk.ECDH()
	if err != nil {
		return "", err
	}

	addr, err := bytesToAddr(pkecdh.Bytes())
	if err != nil {
		return "", err
	}

	return addr, nil
}

// Convert the webauthn format key into ecdsa
func (w Webauthn) getPublicKey() (*ecdsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(w.PublicKey)
	if err != nil {
		return nil, err
	}

	epk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to cast public key to ecdsa.PublicKey")
	}

	return epk, nil
}

// Construct the data that `navigator.credentials.get` used to sign
func (w Webauthn) signedDataHash() [32]byte {
	clientDataHash := sha256.Sum256([]byte(string(w.Response.ClientDataJSON)))
	sigData := append(w.Response.AuthenticatorData, clientDataHash[:]...)
	msgHash := sha256.Sum256(sigData)
	return msgHash
}

// Ensure that the challenge signed by webauthn is the same as the
// hash of the tx
func (w Webauthn) verifyChallenge() bool {
	// The challenge is the hash of the json string
	txHash := sha256.Sum256([]byte(string(w.SerializedTx)))
	// Now pick out the challenge from clientDataJSON
	type clientDataJSON struct {
		Challenge protocol.URLEncodedBase64 `json:"challenge"`
	}
	cdj := clientDataJSON{}
	if err := json.Unmarshal(w.Response.ClientDataJSON, &cdj); err != nil {
		return false
	}
	return txHash == [32]byte(cdj.Challenge)
}

// For fun use Blake to construct our address format
// @pubKeyBytes is *ecdsa.PublicKey{}.ECDH().Bytes()
func bytesToAddr(pubKeyBytes []byte) (string, error) {
	hashedPublicKey, err := blake2b.New(20, nil)
	if err != nil {
		return "", err
	}
	hashedPublicKey.Write(pubKeyBytes)
	versionedHash := append([]byte{0x00}, hashedPublicKey.Sum(nil)...)

	// Generate checksum using BLAKE2b
	checksumHash, err := blake2b.New(32, nil)
	if err != nil {
		return "", err
	}
	checksumHash.Write(versionedHash)
	checksum := checksumHash.Sum(nil)[:4]

	// Form the final address and encode it using Base58Check
	address := append(versionedHash, checksum...)
	base58Address := base58.Encode(address)
	return base58Address, nil
}

// recoverPublicKey recovers the public key from the signature.
// func recoverPublicKey(k *ecdsa.PublicKey, hash []byte, r, s *big.Int, recid int) (*ecdsa.PublicKey, error) {
// 	curve := elliptic.P256() // secp256r1
// 	// params := curve.Params()
// 	if recid < 0 || recid > 3 {
// 		return nil, fmt.Errorf("invalid recid: %d", recid)
// 	}

// 	spew.Dump(k)
// 	for v := 0; v < 4; v++ {
// 		// Try to recover public key
// 		x, y := curve.ScalarBaseMult(hash)
// 		x, y = x.Add(x, new(big.Int).SetInt64(int64(v))), y
// 		if !curve.IsOnCurve(x, y) {
// 			fmt.Println("Not on curve")
// 			continue
// 		}

// 		pubkey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
// 		if ecdsa.Verify(pubkey, hash, r, s) {
// 			fmt.Println("Yep")
// 			spew.Dump(pubkey)
// 			return pubkey, nil
// 		} else {
// 			fmt.Println("Nope")
// 		}
// 	}
// 	return nil, fmt.Errorf("signature verification failed")

// Calculate the candidate public key point.
// x, y := curve.ScalarBaseMult(hash)
// x.Add(x, new(big.Int).SetInt64(int64(recid&2)))
// x.Mod(x, params.P)
// // rx := new(big.Int).Mul(r, x)
// ySquare := new(big.Int).Exp(x, new(big.Int).SetInt64(3), params.P)
// ySquare.Add(ySquare, params.B)
// ySquare.Mod(ySquare, params.P)
// ySquareRoot := new(big.Int).ModSqrt(ySquare, params.P)

// if ySquareRoot == nil {
// 	return nil, fmt.Errorf("no square root found")
// }
// if recid&1 == 1 {
// 	y = new(big.Int).Sub(params.P, ySquareRoot)
// } else {
// 	y = ySquareRoot
// }

// Create a candidate ecdsa.PublicKey
// pubkey := &ecdsa.PublicKey{
// 	Curve: curve,
// 	X:     x,
// 	Y:     y,
// }

// Verify the signature to make sure it's correct
// spew.Dump(k)
// spew.Dump(pubkey)
// if ecdsa.Verify(k, hash, r, s) {
// 	fmt.Println("YEP OK")
// 	return pubkey, nil
// }
// if ecdsa.Verify(pubkey, hash, r, s) {
// 	return pubkey, nil
// }
// return nil, fmt.Errorf("signature verification failed")
// }

// Dcred Bible ecrecover k1 curve
// https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/ecdsa/signature.go#L796

// https://github.com/darkskiez/eckr/blob/master/eckr.go
// func pointsOnCurve(curve *elliptic.CurveParams, x *big.Int) (yp, yn *big.Int) {

// 	y := new(big.Int)
// 	yp = new(big.Int)
// 	yn = new(big.Int)

// 	// y = x^2 - 3
// 	y.Mul(x, x).Mod(y, curve.P)
// 	y.Sub(y, big.NewInt(3)).Mod(y, curve.P)

// 	// y = x^3 - 3x
// 	y.Mul(y, x).Mod(y, curve.P)

// 	// y = x^3 - 3x + b
// 	y.Add(y, curve.B).Mod(y, curve.P)

// 	yp.ModSqrt(y, curve.P)

// 	yn.Sub(curve.P, yp)

// 	return yp, yn
// }

// // RecoverPublicKeys calculates two public keys that may have signed(r,s) the hash.
// func RecoverPublicKeys(curve elliptic.Curve, hash []byte, r, s *big.Int) ([]ecdsa.PublicKey, error) {
// 	if r.Sign() <= 0 {
// 		return nil, errors.New("Signature r must be positive")
// 	}
// 	if s.Sign() <= 0 {
// 		return nil, errors.New("Signature s must be positive")
// 	}

// 	n := curve.Params().N

// 	x := new(big.Int).Mod(r, n)
// 	rp, rn := pointsOnCurve(curve.Params(), x)
// 	rinv := new(big.Int).ModInverse(r, n)

// 	basex, basey := curve.ScalarBaseMult(hash)
// 	negbasey := new(big.Int).Neg(basey)

// 	var keys [2]ecdsa.PublicKey

// 	for i, y := range []*big.Int{rp, rn} {
// 		psrx, psry := curve.ScalarMult(r, y, s.Bytes())
// 		subx, suby := curve.Add(psrx, psry, basex, negbasey)
// 		px, py := curve.ScalarMult(subx, suby, rinv.Bytes())
// 		keys[i] = ecdsa.PublicKey{Curve: curve, X: px, Y: py}
// 	}
// 	return keys[:], nil
// }

// type ECPoint struct {
// 	curve        elliptic.Curve
// 	coords       [2]*big.Int
// 	onCurveKnown bool
// }

// func decompressPoint_P256(curve elliptic.Curve, x *big.Int, sign byte) (*ECPoint, error) {
// 	params := curve.Params()
// 	modP := common.ModInt(params.P)
// 	three := big.NewInt(3)

// 	// P-256/secp256r1/prime256v1: y^2 = x^3 - 3x + b
// 	x3 := modP.Exp(x, three)
// 	threeX := modP.Mul(x, three)

// 	// x^3 - 3x
// 	y2 := new(big.Int).Sub(x3, threeX)
// 	// .. + b mod P
// 	y2 = modP.Add(y2, params.B)

// 	// find the sq root mod P
// 	y := modP.Sqrt(y2)
// 	if y == nil {
// 		return nil, errors.New("DecompressPoint() invalid point")
// 	}
// 	if y.Bit(0) != uint(sign)&1 {
// 		y = modP.Neg(y)
// 	}
// 	return &ECPoint{
// 		curve:  curve,
// 		coords: [2]*big.Int{x, y},
// 	}, nil
// }
