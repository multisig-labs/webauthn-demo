-- name: CreateAccount :one
INSERT INTO accounts (
  address, balance
) VALUES (
  ?, 0
) RETURNING id;

-- name: GetAccountBalance :one
SELECT balance FROM accounts WHERE address = ?;

-- name: UpdateAccountBalance :exec
UPDATE accounts SET balance = ? WHERE address = ?;

-- name: CreateTx :exec
INSERT INTO txs (
  payer, payee, amount, tx_hash, sig
) VALUES (
  ?, ?, ?, ?, ?
);

