import { ECDSASigValue } from "https://esm.sh/@peculiar/asn1-ecc";
import { AsnParser } from "https://esm.sh/@peculiar/asn1-schema";
import { platformAuthenticatorIsAvailable } from "https://esm.sh/@simplewebauthn/browser";
import { toHex, fromHex } from "https://esm.sh/viem@1.10.14";

export async function createKey() {
  let credential = await navigator.credentials.create({
    publicKey: {
      // Does this matter?
      challenge: Uint8Array.from("ohhlala", (c) => c.charCodeAt(0)),
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        requireResidentKey: true,
        residentKey: "required",
      },
      rp: {
        name: "Morpheus",
      },
      // Does this matter?
      user: {
        id: Uint8Array.from("Neo", (c) => c.charCodeAt(0)),
        name: "Neo",
        displayName: "neo@matrix.io",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
  });
  console.log("navigator.credentials.create()", credential);
  const cc = convertCredential(credential);
  return cc;
}

async function sha256(msg) {
  const msgBuffer = new TextEncoder("utf-8").encode(msg);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", msgBuffer);
  // const hashArray = Array.from(new Uint8Array(hashBuffer));
  return bufferToHex(hashBuffer);
}

export async function signTx(tx, pubKey) {
  const hash = await sha256(tx);
  return await signHash(hash, pubKey);
}

export async function signHash(hash, pubKey) {
  const challenge = fromHex(hash, "bytes");
  const publicKey = {
    challenge: challenge,
    userVerification: "required",
  };

  let resp = await navigator.credentials.get({ publicKey });
  console.log("navigator.credentials.get()", resp);
  const convResp = convertGetResponse(resp);
  convResp.publicKey = pubKey;
  console.log("navigator.credentials.get()", convResp);
  return convResp;
}

function convertCredential(credential) {
  const { id, rawId, response, type } = credential;

  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    type,
    publicKey: bufferToBase64URLString(response.getPublicKey()),
  };
}

function convertGetResponse(webauthnResponse) {
  return {
    type: webauthnResponse.type,
    id: webauthnResponse.id,
    rawId: bufferToBase64URLString(webauthnResponse.rawId),
    response: convertPropertiesToBase64URLString(webauthnResponse.response, [
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

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return toHex(bytes);
}

export function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = "";

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function webauthnSupported() {
  return Boolean(
    navigator.credentials?.create &&
      navigator.credentials?.get &&
      window.PublicKeyCredential
  );
}

function base64URLStringToBuffer(base64URLString) {
  // Convert from Base64URL to Base64
  const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
  /**
   * Pad with '=' until it's a multiple of four
   * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
   * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
   * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
   * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
   */
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, "=");

  // Convert to a binary string
  const binary = atob(padded);

  // Convert binary string to buffer
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return buffer;
}
