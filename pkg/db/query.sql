-- name: CreateAccount :one
INSERT INTO accounts (
  address
) VALUES (
  ?
) RETURNING id;

-- name: GetAccountBalance :one
SELECT balance FROM accounts WHERE address = ?;

-- name: UpdateAccountBalance :exec
UPDATE accounts SET balance = ? WHERE address = ?;

-- name: MaxHeight :one
SELECT cast(COALESCE(max(height),0) as integer) as maxheight from txs;

-- name: CreateTx :exec
INSERT INTO txs (
  id, height, payer, payee, amount
) VALUES (
  ?, ?, ?, ?, ?
);

