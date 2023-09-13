package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

func (handler *HealthHandler) Alive(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{"alive": true})
}
