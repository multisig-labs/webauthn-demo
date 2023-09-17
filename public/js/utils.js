import { ECDSASigValue } from "https://unpkg.com/@peculiar/asn1-ecc";
import { AsnParser } from "https://unpkg.com/@peculiar/asn1-schema";

// Helper functions from @simplewebauthn/server
function shouldRemoveLeadingZero(bytes) {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

function fromUTF8String(utf8String) {
  const encoder = new globalThis.TextEncoder();
  return encoder.encode(utf8String);
}

async function digest(data, _algorithm) {
  const hashed = await crypto.subtle.digest("SHA-256", data);

  return new Uint8Array(hashed);
}

async function toHash(data, algorithm = -7) {
  if (typeof data === "string") {
    data = fromUTF8String(data);
  }

  return digest(data, algorithm);
}

function concat(arrays) {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

async function verifyAuthentication(authJson) {
  // 1. Creates the digest WebAuthn signs, see https://github.com/MasterKale/SimpleWebAuthn/blob/6f363aa53a69cf8c1ea69664924c1e9f8e19dc4e/packages/server/src/authentication/verifyAuthenticationResponse.ts#L189
  const authDataBuffer = base64url.toBuffer(
    authJson.response.authenticatorData
  );
  const clientDataHash = await toHash(
    base64url.toBuffer(authJson.response.clientDataJSON)
  );

  const signatureBase = concat([authDataBuffer, clientDataHash]);

  // 2. Retrieving the r and s values, see https://github.com/MasterKale/SimpleWebAuthn/blob/6f363aa53a69cf8c1ea69664924c1e9f8e19dc4e/packages/server/src/helpers/iso/isoCrypto/verifyEC2.ts#L103
  const parsedSignature = AsnParser.parse(
    base64url.toBuffer(authJson.response.signature),
    ECDSASigValue
  );
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  // 3. Recover the Ethereum address from the digest and the signature
  const finalSignature = ethers.utils.concat([rBytes, sBytes]);
  return ethers.utils.recoverAddress(signatureBase, finalSignature);
}
/**
 * String to Array Buffer
 * @param str string to convert
 */
export const str2ab = (str) => {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
};

/**
 * Buffer to Base64 url-encoded string
 * @param buffer buffer to convert
 */
export const bufferToBase64URLString = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let str = "";

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};
