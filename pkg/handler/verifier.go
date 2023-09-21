package handler

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/multisig-labs/webauthn-demo/pkg/secp256r1"
)

type VerifierHandler struct{}

func NewVerifierHandler() *VerifierHandler {
	return &VerifierHandler{}
}

type VerifyBody struct {
	PublicKey string `json:"pubKey" validate:"required,hexadecimal"`
	MsgHash   string `json:"msgHash" validate:"required,hexadecimal"`
	Msg       string `json:"msg"`
	Signature string `json:"sig" validate:"required,hexadecimal"`
}

func (v VerifyBody) ToBytes() (publicKey, msgHash, signature []byte, errs error) {
	publicKey, err := hex.DecodeString(strings.TrimPrefix(v.PublicKey, "0x"))
	errs = errors.Join(errs, err)
	msgHash, err = hex.DecodeString(strings.TrimPrefix(v.MsgHash, "0x"))
	errs = errors.Join(errs, err)
	signature, err = hex.DecodeString(strings.TrimPrefix(v.Signature, "0x"))
	errs = errors.Join(errs, err)
	return
}

func (handler *VerifierHandler) Verify(c echo.Context) error {
	body, err := bindAndValidate[VerifyBody](c)
	if err != nil {
		return toHttpError(err)
	}
	publicKey, msgHash, signature, err := body.ToBytes()
	if err != nil {
		return toHttpError(err)
	}

	pk, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return toHttpError(err)
	}
	epk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return toHttpError(fmt.Errorf("unable to cast public key to ecdsa.PublicKey"))
	}

	ok = secp256r1.VerifySignature(epk, msgHash, signature)
	return c.JSON(http.StatusOK, map[string]bool{"ok": ok})
}
