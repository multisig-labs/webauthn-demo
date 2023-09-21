package handler

import (
	"crypto/ecdsa"
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
