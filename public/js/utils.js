// Helper for fetching a POST
export async function post(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return await resp.json();
}

export function concat(arrays) {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

// String to Array Buffer
export function str2ab(str) {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export async function sha256(msg) {
  const msgBuffer = new TextEncoder("utf-8").encode(msg);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", msgBuffer);
  return bufferToHex(hashBuffer);
}

export function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return toHexString(bytes);
}

export function hexToBuffer(hexString) {
  if (hexString.startsWith("0x")) {
    hexString = hexString.slice(2);
  }

  const buffer = new ArrayBuffer(hexString.length / 2);
  const view = new DataView(buffer);

  // Iterate over the hex string, two characters at a time.
  for (let i = 0; i < hexString.length; i += 2) {
    // Parse the hex code into a byte.
    const byte = parseInt(hexString.slice(i, i + 2), 16);
    view.setUint8(i / 2, byte);
  }

  return buffer;
}

export function arrayToObject(arr) {
  return arr.reduce((obj, [key, value]) => ({ ...obj, [key]: value }), {});
}

export function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = "";

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }
  return stringToBase64URLString(str);
}

export function stringToBase64URLString(str) {
  const base64String = btoa(str);
  return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function base64URLStringToBuffer(base64URLString) {
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
