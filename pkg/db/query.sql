-- name: CreateAccount :exec
INSERT INTO accounts (
  address, balance
) VALUES (
  ?, ?
);

-- name: UpdateAccount :exec
INSERT INTO accounts (address, balance)
VALUES (?, ?)
ON CONFLICT(address)
DO UPDATE
SET balance = balance + excluded.balance;

-- name: GetAccounts :many
SELECT address, balance
FROM accounts
ORDER BY address
LIMIT 500;

-- name: GetAccountBalance :one
SELECT balance FROM accounts WHERE address = ?;

-- name: CreateTx :exec
INSERT INTO txs (
  payer, payee, amount
) VALUES (
  ?, ?, ?
);

-- name: GetTxs :many
SELECT height, payer, payee, amount
FROM txs
ORDER BY height desc
LIMIT 500;