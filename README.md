# Webauthn for Crypto Demo

Imagine a world where signing crypto transactions was as seamless as using ApplePay. Well that day is coming soon. All the pieces are in place. Unfortunately, legacy L1 blockchains will be unable to take full advantage. But if we start with a latest generation blockchain system and bake this new technology into it from the start, magic can happen!

So, we tried fitting some of the existing Lego pieces together, to see how far we could get. This repo is a demo of using the Webauthn APIs to create a private key (wallet) that lives on your device or on your phone, and then using that key to sign transactions, and send them to a Go backend where they are cryptographically verified.

This is a **very** rough demo, just trying to see how all the pieces copuld potentially fit together. The code is very much a WIP.

Longer blog post about our journey can be found [here](https://gogo-webauthn.fly.dev/blog)

## Install

Install [Go](https://go.dev/learn/):

`brew install golang`

Install [Just](https://github.com/casey/just), the modern Make replacement:

`brew install just`

Install [SqlC](https://sqlc.dev/), 'cause we don't use no ORMs 'round here:

`brew install sqlite3 sqlc`

## Run

`just build`

`just create-db`

`just serve`

Navigate to http://localhost:8000/home and try it out!

Or find it [on the web](https://gogo-webauthn.fly.dev/home)
