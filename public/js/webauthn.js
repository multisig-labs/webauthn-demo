import { ECDSASigValue } from "https://esm.sh/@peculiar/asn1-ecc";
import { AsnParser } from "https://esm.sh/@peculiar/asn1-schema";
import { platformAuthenticatorIsAvailable } from "https://esm.sh/@simplewebauthn/browser";

(async () => {
  if (await platformAuthenticatorIsAvailable()) {
    console.log("avail");
  }
})();
