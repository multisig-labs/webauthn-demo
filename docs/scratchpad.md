# Command Scratchpad

just clean && just create-db
just build && DEV_MODE=true bin/webauthn serve

restish post :8000/account -f body "Address: 1a, Balance: 100"
restish post :8000/account -f body "Address: 1b, Balance: 100"
restish get :8000/accounts -f body -t

restish post :8000/tx -f body "tx_hash: h3, from: 0x01, to: 0x02, amount: 1, tx: todo, raw_tx: todo"
restish get :8000/txs -f body -t
