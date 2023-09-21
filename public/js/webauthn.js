import { get, set, clear, entries } from "https://esm.sh/idb-keyval@6.2.1";
import canonicalize from "https://esm.sh/canonicalize@2.0.0";
import { blake2b } from "https://esm.sh/blakejs@1.2.1";
import bs58 from "https://esm.sh/bs58@5.0.0";
import {
  arrayToObject,
  bufferToBase64URLString,
  sha256,
  base64URLStringToBuffer,
  stringToBase64URLString,
  hexToBuffer,
} from "/js/utils.js";

// https://w3c.github.io/webauthn/#sctn-public-key-easy
// @publicKey is ArrayBuffer of ASN.1 DER format bytes (as from getPublicKey())
export async function pubkeyAddress(publicKeyBuffer) {
  const pubkey = await window.crypto.subtle.importKey(
    "spki",
    new Uint8Array(publicKeyBuffer),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    []
  );
  const rawBytes = await crypto.subtle.exportKey("raw", pubkey);

  const hashedPublicKey = blake2b(new Uint8Array(rawBytes), null, 20);
  // Add version byte
  const versionByte = [0x00];
  const versionedHash = new Uint8Array([...versionByte, ...hashedPublicKey]);
  // Generate checksum using BLAKE2b
  const checksum = blake2b(versionedHash, null, 32).slice(0, 4);
  // Form the final address and encode it using Base58Check
  const address = new Uint8Array([...versionedHash, ...checksum]);
  const base58Address = bs58.encode(address);
  return base58Address;
}

// Create new key then save id and pubkey to local db
// Webauthn doesnt let you list keys or retrieve the pubkey later,
// so we have to capture and store this info ourselves somewhere,
// for this demo we use a local indexedDB
export async function createWallet(relyingParty, walletName = "", mobileOnly = false) {
  // Dont allow overwriting an existing key
  const wallet = await get(walletName);
  if (wallet === undefined) {
    const key = await createKey(relyingParty, walletName, walletName, mobileOnly);
    key.walletName = walletName;
    await set(walletName, key);
    return key;
  } else {
    const msg = `Cannot overwrite wallet: ${walletName}`;
    console.log(msg);
    return { error: msg };
  }
}

export async function getWallets() {
  const ent = await entries();
  return arrayToObject(ent);
}

export function clearWallets() {
  clear();
}

// Returns a signed transaction which is a combination of the results from
// navigator.credential.get and the publicKey, for verification by the Go lib
export async function signTx(walletName, tx) {
  const wallets = await getWallets();
  const wallet = wallets[walletName];
  if (!wallet) {
    return { error: "Wallet does not exist" };
  }
  if (typeof tx != "object") {
    return { error: "tx must be an object" };
  }

  // To be consistent with how webauthn encodes things, we will canonicalize the JSON
  // then sign that, then encode to base64URL for transport
  const canonTx = canonicalize(tx);
  console.log("CanonicalizedJSON:", canonTx);
  const bytesHex = await sha256(canonTx);
  console.log("Hash of canonTx to use as challenge:", bytesHex);
  const webauthnResponse = await signChallenge(wallet, bytesHex);
  return convertGetResponse(wallet, canonTx, webauthnResponse);
}

async function createKey(relyingParty, userId, userName, mobileOnly) {
  const opts = {
    publicKey: {
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      challenge: Uint8Array.from("notused", (c) => c.charCodeAt(0)),
      authenticatorSelection: {
        authenticatorAttachment: mobileOnly ? "cross-platform" : "platform",
        requireResidentKey: true,
        residentKey: "required",
        userVerification: "required",
      },
      rp: {
        // if id not specified, defaults to domain of whatever page you are on
        // id: "localhost",
        name: relyingParty,
      },
      user: {
        id: Uint8Array.from(userId, (c) => c.charCodeAt(0)),
        name: userName,
        displayName: userName,
      },
    },
  };
  let credential = await navigator.credentials.create(opts);
  const publicKey = await convertCredential(credential);
  console.log("navigator.credentials.create", opts, credential, publicKey);
  return publicKey;
}

async function signChallenge(wallet, bytesHex) {
  const id = base64URLStringToBuffer(wallet.id);
  const challenge = hexToBuffer(bytesHex);
  const publicKey = {
    challenge: challenge,
    userVerification: "required",
    allowCredentials: [{ type: "public-key", id: id }],
  };

  let getResponse = await navigator.credentials.get({ publicKey });
  console.log("navigator.credentials.get", publicKey, getResponse);
  return getResponse;
}

async function convertCredential(credential) {
  const { id, response } = credential;
  const publicKey = bufferToBase64URLString(response.getPublicKey());
  const address = await pubkeyAddress(response.getPublicKey());
  return {
    id,
    publicKey,
    address,
  };
}

// Convert a webauthn obj into an obj that the Go lib will use to verify the signature
function convertGetResponse(wallet, serializedTx, webauthnResponse) {
  return {
    walletId: webauthnResponse.id,
    walletName: wallet.walletName,
    publicKey: wallet.publicKey,
    serializedTx: stringToBase64URLString(serializedTx),
    webauthnResponse: convertPropertiesToBase64URLString(webauthnResponse.response, [
      "clientDataJSON",
      "authenticatorData",
      "signature",
      "userHandle",
    ]),
  };
}

function convertPropertiesToBase64URLString(obj, props) {
  return props.reduce(
    (acc, property) =>
      Object.assign(acc, {
        [property]: bufferToBase64URLString(obj[property]),
      }),
    {}
  );
}
