package handler

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/multisig-labs/webauthn-demo/pkg/db"
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

type GetBalanceBody struct {
	Address string `json:"address" validate:"required"`
}

type GetBalanceResponse struct {
	Address string `json:"address"`
	Balance int64  `json:"balance"`
}

func (h *ApiHandler) GetBalance(c echo.Context) error {
    address := c.QueryParam("address")
    if address == "" {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "address query parameter is required",
        })
    }

    ctx := context.Background()
    bal, err := h.q.GetAccountBalance(ctx, address)
    if err != nil {
        return toHttpError(err)
    }

    r := GetBalanceResponse{
        Address: address,
        Balance: bal,
    }

    return c.JSON(http.StatusOK, r)
}

type CreateTxBody struct {
	FromAddress string `json:"from_address" validate:"required"`
	ToAddress   string `json:"to_address" validate:"required"`
	Amount      int64  `json:"amount" validate:"required"`
	TxHash 		string `json:"tx_hash" validate:"required"`
	Sig 		string `json:"sig" validate:"required"`
}

type CreateTxResponse struct {
	Tx *db.Tx `json:"tx"`
}

func (h *ApiHandler) CreateTx(c echo.Context) error {
	body, err := bindAndValidate[CreateTxBody](c)
	if err != nil {
		return toHttpError(err)
	}

	ctx := context.Background()
	args := db.CreateTxParams{
		Payer:  body.FromAddress,
		Payee:  body.ToAddress,
		Amount: body.Amount,
		TxHash: body.TxHash,
		Sig:    body.Sig,
	}
	// Create transaction
	err = h.q.CreateTx(ctx, args)
	if err != nil {
		return toHttpError(err)
	}
	// Get sender balance
	senderBalance, err := h.q.GetAccountBalance(ctx, body.FromAddress)
	if err != nil {
		return toHttpError(err)
	}
	// Get receiver balance
	receiverBalance, err := h.q.GetAccountBalance(ctx, body.ToAddress)
	if err != nil {
		return toHttpError(err)
	}
	// Update sender balance
	senderParams := db.UpdateAccountBalanceParams{
		Balance: senderBalance - body.Amount,
		Address: body.FromAddress,
	}
	err = h.q.UpdateAccountBalance(ctx, senderParams)
	if err != nil {
		return toHttpError(err)
	}
	// Update receiver balance
	receiverParams := db.UpdateAccountBalanceParams{
		Balance: receiverBalance + body.Amount,
		Address: body.ToAddress,
	}
	err = h.q.UpdateAccountBalance(ctx, receiverParams)
	if err != nil {
		return toHttpError(err)
	}

	return c.JSON(http.StatusOK, nil)
}