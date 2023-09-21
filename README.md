# WebAuthn Playground

# 💡Idea

Do crypto with WebAuthn

restish post :8000/verify pubKey: 0x03b434054a968479e6d1adb7b6185d1373c5b8f9cdd0813028327e6a342d702df6, dataHash: 0x989a647219cb0c3de61ec045ea197b8c48e8e40bc3fda8b93033b96b109a222a, sig: 0x3045022074bcdc20e53b9342b8dad74aa65dfc8c0b80c3963f596440452316c762fa4b81022100f693c4b11ca20c3cffe96a4d0f404fcfeaf4b954d3d4dd162fe156381de654a6

https://github.com/zkwebauthn/webauthn-halo2/blob/main/web-demo/src/pages/index.tsx

discussion for eth acct abstraction support
https://ethresear.ch/t/passkey-based-account-abstraction-signer-for-smart-contract-wallets/15856

Starknet
https://hackmd.io/@tarrence/rk3ksuqSo

https://app.joyid.dev/

https://github.com/sui-foundation/sips/pull/9#issuecomment-1694669233

https://archive.nervos.org/blog/joyid-a-passwordless-web3-wallet-that-will-accelerate-the-mass-adoption-for-nervos

https://medium.com/alembic-tech/why-biometric-wallets-are-the-future-of-web3-14ad1e3c88f0

https://hackmd.io/@tarrence/rk3ksuqSo

https://ethresear.ch/t/passkey-based-account-abstraction-signer-for-smart-contract-wallets/15856/20

    // Private/public key pair was generated with the following:
    //
    // $ openssl ecparam -genkey -name secp256r1 -noout -out private_key.pem
    // $ openssl ec -in private_key.pem -noout -text
    // Private-Key: (256 bit)
    // priv:
    // 	48:7f:36:1d:df:d7:34:40:e7:07:f4:da:a6:77:5b:
    // 	37:68:59:e8:a3:c9:f2:9b:3b:b6:94:a1:29:27:c0:
    // 	21:3c
    // pub:
    // 	04:f7:39:f8:c7:7b:32:f4:d5:f1:32:65:86:1f:eb:
    // 	d7:6e:7a:9c:61:a1:14:0d:29:6b:8c:16:30:25:08:
    // 	87:03:16:c2:49:70:ad:78:11:cc:d9:da:7f:1b:88:
    // 	f2:02:be:ba:c7:70:66:3e:f5:8b:a6:83:46:18:6d:
    // 	d7:78:20:0d:d4
    // ASN1 OID: prime256v1
    // NIST CURVE: P-256
    // ----.

    // Private/public key pair was generated with the following:
    //
    // $ openssl ecparam -genkey -name secp256r1 -noout -out private_key.pem
    // $ openssl ec -in private_key.pem -noout -text
    // Private-Key: (256 bit)
    // priv:
    // 	48:7f:36:1d:df:d7:34:40:e7:07:f4:da:a6:77:5b:
    // 	37:68:59:e8:a3:c9:f2:9b:3b:b6:94:a1:29:27:c0:
    // 	21:3c
    // pub:
    // 	04:f7:39:f8:c7:7b:32:f4:d5:f1:32:65:86:1f:eb:
    // 	d7:6e:7a:9c:61:a1:14:0d:29:6b:8c:16:30:25:08:
    // 	87:03:16:c2:49:70:ad:78:11:cc:d9:da:7f:1b:88:
    // 	f2:02:be:ba:c7:70:66:3e:f5:8b:a6:83:46:18:6d:
    // 	d7:78:20:0d:d4
    // ASN1 OID: prime256v1
    // NIST CURVE: P-256
    // ----.
    pubX, err := hex.DecodeString("f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316")
    assert.Nil(t, err)
    pubY, err := hex.DecodeString("c24970ad7811ccd9da7f1b88f202bebac770663ef58ba68346186dd778200dd4")
    assert.Nil(t, err)

    key := EC2PublicKeyData{
    	// These constants are from https://datatracker.ietf.org/doc/rfc9053/
    	// (see "ECDSA" and "Elliptic Curve Keys").
    	PublicKeyData: PublicKeyData{
    		KeyType:   2,  // EC.
    		Algorithm: -7, // "ES256".
    	},
    	Curve:  1, // P-256.
    	XCoord: pubX,
    	YCoord: pubY,
    }

    data := []byte("webauthnFTW")

    // Valid signature obtained with:
    // $ echo -n 'webauthnFTW' | openssl dgst -sha256 -sign private_key.pem | xxd -ps | tr -d '\n'.
    validSig, err := hex.DecodeString("3045022053584980793ee4ec01d583f303604c4f85a7e87df3fe9551962c5ab69a5ce27b022100c801fd6186ca4681e87fbbb97c5cb659f039473995a75a9a9dffea2708d6f8fb")
    assert.Nil(t, err)

    // Happy path, verification should succeed.
    ok, err := VerifySignature(key, data, validSig)
    assert.True(t, ok, "invalid EC signature")
    assert.Nil(t, err, "error verifying EC signature")

# Recover PubKey via signature

If you have pubkey, msghash, and sig, you can easily do:

`secp256r1.VerifySignature(publicKey, dataHash, signature)`

If you only have msghasg and sig (like in Ethereum land) then you need to write `ecrecover` like these guys did

https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/ecdsa/signature.go#L786

for the k1 curve.

So take `secp256r1.VerifySignature` from the Go `ecdsa` package, and modify it?

The reason this is a probelm is because, `navigator.credentials.get` DOES NOT give you the public key, only the sig. :( So a workaround is to save off the pub key when doing `navigator.credentials.create`

# Links

https://github.com/Banana-Wallet/banana-passkey-eoa/tree/main

https://ethresear.ch/t/passkey-based-account-abstraction-signer-for-smart-contract-wallets/15856?page=2

https://github.com/indutny/elliptic/blob/43ac7f230069bd1575e1e4a58394a512303ba803/lib/elliptic/ec/index.js#L196

https://ethereum-magicians.org/t/eip-7212-precompiled-for-secp256r1-curve-support/14789/42

# Constructing data that was signed

https://github.com/MasterKale/SimpleWebAuthn/blob/e02dce6f2f83d8923f3a549f84e0b7b3d44fa3da/packages/server/src/authentication/verifyAuthenticationResponse.ts#L205C3-L208C80

```js
const clientDataHash = await toHash(
  isoBase64URL.toBuffer(assertionResponse.clientDataJSON)
);
const signatureBase = isoUint8Array.concat([authDataBuffer, clientDataHash]);
```

https://github.com/go-webauthn/webauthn/blob/709be4f6e0357862b4a5fcda5d27aff2d8dda6a4/protocol/assertion.go#L153

```go
	// Step 15. Let hash be the result of computing a hash over the cData using SHA-256.
	clientDataHash := sha256.Sum256(p.Raw.AssertionResponse.ClientDataJSON)

	// Step 16. Using the credential public key looked up in step 3, verify that sig is
	// a valid signature over the binary concatenation of authData and hash.

	sigData := append(p.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)
```
