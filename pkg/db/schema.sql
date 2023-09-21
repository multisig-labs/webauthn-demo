-- Dummy blockchain API for doing fake transactions. 

CREATE TABLE accounts (
  address text PRIMARY KEY,
  balance integer NOT NULL CHECK(balance > 0)
) STRICT;

CREATE TABLE txs (
  height integer PRIMARY KEY,
  payer text NOT NULL REFERENCES accounts(address),
  payee text NOT NULL REFERENCES accounts(address),
  amount integer NOT NULL
) STRICT;

-- Deducting the amount from the payer's account
CREATE TRIGGER update_payer_balance
AFTER INSERT ON txs
BEGIN
  UPDATE accounts 
  SET balance = balance - NEW.amount 
  WHERE address = NEW.payer;
END;

-- Adding the amount to the payee's account
CREATE TRIGGER update_payee_balance
AFTER INSERT ON txs
BEGIN
  UPDATE accounts 
  SET balance = balance + NEW.amount 
  WHERE address = NEW.payee;
END;

-- Look ma, I'm immutable!
CREATE TRIGGER txs_trigger_update
BEFORE UPDATE ON txs
BEGIN
  SELECT RAISE(ABORT, 'Update operation is prohibited!');
END;

CREATE TRIGGER txs_trigger_delete
BEFORE DELETE ON txs
BEGIN
  SELECT RAISE(ABORT, 'Delete operation is prohibited!');
END;