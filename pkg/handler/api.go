package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/multisig-labs/webauthn-demo/pkg/db"
	"github.com/multisig-labs/webauthn-demo/pkg/webauthn"
)

type ApiHandler struct {
	dbFilename string
	dbFile     *sql.DB
	q          *db.Queries
}

func NewApiHandler(dbFilename string) *ApiHandler {
	dbFile, queries := db.OpenDB(dbFilename)
	return &ApiHandler{dbFilename: dbFilename, dbFile: dbFile, q: queries}
}

// GET /account/:address
func (h *ApiHandler) GetAccount(c echo.Context) error {
	address := c.Param("address")
	if address == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "address path parameter is required",
		})
	}

	ctx := context.Background()
	bal, err := h.q.GetAccountBalance(ctx, address)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, map[string]int64{"balance": bal})
}

// GET /accounts
func (h *ApiHandler) GetAccounts(c echo.Context) error {
	ctx := context.Background()
	bals, err := h.q.GetAccounts(ctx)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, bals)
}

// POST /account
func (h *ApiHandler) CreateAccount(c echo.Context) error {
	body, err := bindAndValidate[db.CreateAccountParams](c)
	if err != nil {
		return toHttpError(err)
	}

	ctx := context.Background()
	err = h.q.CreateAccount(ctx, body)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

// POST /update_account
func (h *ApiHandler) UpdateAccount(c echo.Context) error {
	body, err := bindAndValidate[db.UpdateAccountParams](c)
	if err != nil {
		return toHttpError(err)
	}

	ctx := context.Background()
	err = h.q.UpdateAccount(ctx, body)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

// GET /txs
func (h *ApiHandler) GetTxs(c echo.Context) error {
	ctx := context.Background()
	txs, err := h.q.GetTxs(ctx)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, txs)
}

// POST /txs
func (h *ApiHandler) CreateTx(c echo.Context) error {
	body, err := bindAndValidate[webauthn.Webauthn](c)
	if err != nil {
		return toHttpError(err)
	}

	if _, err := body.Verify(); err != nil {
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
	}

	args := db.CreateTxParams{}
	err = json.Unmarshal(body.SerializedTx, &args)
	if err != nil {
		return toHttpError(err)
	}

	ctx := context.Background()
	err = h.q.CreateTx(ctx, args)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}
