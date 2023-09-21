package handler

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

type WebauthnHandler struct{}

func NewWebauthnHandler() *WebauthnHandler {
	return &WebauthnHandler{}
}

// func (handler *WebauthnHandler) VerifySig(c echo.Context, ) {
// parsedResponse, err := protocol.ParseCredentialCreationResponse(response)
// if err = json.NewDecoder(body).Decode(&ccr); err != nil {
// 		return nil, ErrBadRequest.WithDetails("Parse error for Registration").WithInfo(err.Error())
// 	}

// 	return ccr.Parse()
// }

// Front end will send the AuthenticatorAssertionResponse (base64URL encoded)
// plus the publicKey obtained from `getPublicKey()`
// and the Tx (the hash of which is the challenge)
type Webauthn struct {
	// Must be result of calling `getPublicKey()` on FE
	PublicKey protocol.URLEncodedBase64 `json:"publicKey"`
	// Whatever TX format we decide on goes here
	Tx string `json:"tx"`
	// AuthenticatorAssertionResponse (binary fields encoded as base64URL)
	Response struct {
		ClientDataJSON    protocol.URLEncodedBase64 `json:"clientDataJSON"`
		AuthenticatorData protocol.URLEncodedBase64 `json:"authenticatorData"`
		Signature         protocol.URLEncodedBase64 `json:"signature"`
	} `json:"response"`
}

func (w Webauthn) GetPublicKey() (*ecdsa.PublicKey, error) {
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

// Construct the data that the `navigator.credentials.get` used to sign
func (w Webauthn) SignedDataHash() [32]byte {
	clientDataHash := sha256.Sum256([]byte(string(w.Response.ClientDataJSON)))
	sigData := append(w.Response.AuthenticatorData, clientDataHash[:]...)
	msgHash := sha256.Sum256(sigData)
	return msgHash
}

func (w Webauthn) Verify() (bool, error) {
	k, err := w.GetPublicKey()
	if err != nil {
		return false, err
	}
	h := w.SignedDataHash()
	ok := ecdsa.VerifyASN1(k, h[:], w.Response.Signature)
	return ok, nil
}

// Used for just picking out the pubkey from the webauthn registration JSON
type ccrResponse struct {
	Response struct {
		PublicKey protocol.URLEncodedBase64 `json:"publicKey"`
	} `json:"response"`
}

func ccrToPubKey(js string) (*ecdsa.PublicKey, error) {
	ccr := ccrResponse{}
	err := json.Unmarshal([]byte(js), &ccr)
	if err != nil {
		return nil, err
	}
	pk, err := x509.ParsePKIXPublicKey(ccr.Response.PublicKey)
	if err != nil {
		return nil, err
	}
	epk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to cast public key to ecdsa.PublicKey")
	}
	return epk, nil
}

// Given CredentialCreationResponse JSON string, parse out the pub key
// (the hard way) from the Attestation Object
func ccrToPubKey2(js string) (*webauthncose.EC2PublicKeyData, error) {
	ccr := protocol.CredentialCreationResponse{}
	err := json.Unmarshal([]byte(js), &ccr)
	if err != nil {
		return nil, err
	}
	ar, err := ccr.AttestationResponse.Parse()
	if err != nil {
		return nil, err
	}
	pubKey, err := webauthncose.ParsePublicKey(ar.AttestationObject.AuthData.AttData.CredentialPublicKey)
	if err != nil {
		return nil, err
	}
	pk, ok := pubKey.(webauthncose.EC2PublicKeyData)
	if !ok {
		return nil, fmt.Errorf("unable to cast public key to webauthncose.EC2PublicKeyData")
	}
	// valid, err = e.Verify(signatureData, sig)
	return &pk, nil
}
