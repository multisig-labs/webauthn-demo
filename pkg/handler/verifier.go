package handler

import (
	"encoding/hex"
	"errors"
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
	DataHash  string `json:"dataHash" validate:"required,hexadecimal"`
	Signature string `json:"sig" validate:"required,hexadecimal"`
}

func (v VerifyBody) ToBytes() (publicKey, dataHash, signature []byte, errs error) {
	publicKey, err := hex.DecodeString(strings.TrimPrefix(v.PublicKey, "0x"))
	errs = errors.Join(errs, err)
	dataHash, err = hex.DecodeString(strings.TrimPrefix(v.DataHash, "0x"))
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
	publicKey, dataHash, signature, err := body.ToBytes()
	if err != nil {
		return toHttpError(err)
	}
	ok := secp256r1.VerifySignature(publicKey, dataHash, signature)
	return c.JSON(http.StatusOK, map[string]bool{"ok": ok})
}
