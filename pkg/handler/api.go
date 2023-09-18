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
	body, err := bindAndValidate[GetBalanceBody](c)
	if err != nil {
		return toHttpError(err)
	}

	ctx := context.Background()
	bal, err := h.q.GetAccountBalance(ctx, body.Address)
	if err != nil {
		return toHttpError(err)
	}

	r := GetBalanceResponse{
		Address: body.Address,
		Balance: bal,
	}

	return c.JSON(http.StatusOK, r)
}
