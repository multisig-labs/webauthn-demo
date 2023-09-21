import { ECDSASigValue } from "https://esm.sh/@peculiar/asn1-ecc";
import { AsnParser } from "https://esm.sh/@peculiar/asn1-schema";
import { platformAuthenticatorIsAvailable } from "https://esm.sh/@simplewebauthn/browser";
import { toHex, fromHex } from "https://esm.sh/viem@1.10.14";

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

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
        displayName: "neo2@matrix.io",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
  });
  console.log(credential);
  window.z = credential;
  const cc = convertCredential(credential);
  console.log(cc);
  return cc;
}

async function sha256(msg) {
  const msgBuffer = new TextEncoder("utf-8").encode(msg);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", msgBuffer);
  // const hashArray = Array.from(new Uint8Array(hashBuffer));
  return bufferToHex(hashBuffer);
}

export async function signMsg(msg) {
  const hash = await sha256(msg);
  const sig = await signHash(hash);
  return { hash, sig };
}

export async function signHash(hash) {
  hash = hash || "";
  if (hash == "") {
    console.log("empty hash");
    return;
  }

  const challenge = fromHex(hash, "bytes");
  const publicKey = {
    challenge: challenge,
    userVerification: "required",
  };

  let resp = await navigator.credentials.get({ publicKey });
  console.log("hash", hash);
  console.log(resp);
  const convResp = convertGetResponse(resp);
  console.log(convResp);
  const sigb = new Uint8Array(resp.response.signature);
  console.log("hex sig:", toHex(sigb));
  return toHex(sigb);
}

function convertPropertiesToBase64(obj, props) {
  return props.reduce(
    (acc, property) =>
      Object.assign(acc, { [property]: bufferToBase64(obj[property]) }),
    {}
  );
}

function bufferToBase64(input) {
  if (typeof input === "string") {
    return input;
  }
  const arr = new Uint8Array(input);
  return btoa(String.fromCharCode(...arr));
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

// https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/methods/startRegistration.ts
function convertCredential(credential) {
  const { id, rawId, response, type } = credential;
  // Continue to play it safe with `getTransports()` for now, even when L3 types say it's required
  let transports = undefined;
  if (typeof response.getTransports === "function") {
    transports = response.getTransports();
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responsePublicKeyAlgorithm = undefined;
  if (typeof response.getPublicKeyAlgorithm === "function") {
    responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm();
  }

  let responsePublicKey = undefined;
  if (typeof response.getPublicKey === "function") {
    const _publicKey = response.getPublicKey();
    if (_publicKey !== null) {
      responsePublicKey = bufferToBase64URLString(_publicKey);
    }
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responseAuthenticatorData = undefined;
  if (typeof response.getAuthenticatorData === "function") {
    responseAuthenticatorData = bufferToBase64URLString(
      response.getAuthenticatorData()
    );
  }

  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      attestationObject: bufferToBase64URLString(response.attestationObject),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      transports,
      publicKeyAlgorithm: responsePublicKeyAlgorithm,
      publicKey: responsePublicKey,
      authenticatorData: responseAuthenticatorData,
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
    // HACK adding for convenience for now
    publicKeyHex: bufferToHex(response.getPublicKey()),
  };
}

function convertGetResponse(webauthnResponse) {
  return {
    type: webauthnResponse.type,
    id: webauthnResponse.id,
    rawId: bufferToBase64(webauthnResponse.rawId),
    response: convertPropertiesToBase64(webauthnResponse.response, [
      "clientDataJSON",
      "authenticatorData",
      "signature",
      "userHandle",
    ]),
    clientExtensionResults: webauthnResponse.getClientExtensionResults(),
  };
}

function webauthnSupported() {
  return Boolean(
    navigator.credentials?.create &&
      navigator.credentials?.get &&
      window.PublicKeyCredential
  );
}
