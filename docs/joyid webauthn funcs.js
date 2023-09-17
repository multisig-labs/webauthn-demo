async function startRegistration(o) {
  const $ = {
    publicKey: {
      ...o,
      authenticatorSelection: {
        ...o.authenticatorSelection,
        authenticatorAttachment: "platform",
      },
      challenge: base64URLStringToBuffer(o.challenge),
      user: { ...o.user, id: utf8StringToBuffer(o.user.id) },
      excludeCredentials: o.excludeCredentials.map(
        toPublicKeyCredentialDescriptor
      ),
      timeout: REGISTRATION_TIMEOUT,
    },
  };
  $.signal = webauthnAbortService.createNewAbortSignal();
  let j;
  const et = window.performance.now();
  try {
    j = await navigator.credentials.create({ ...$ });
  } catch (at) {
    throw identifyRegistrationError({ error: at, options: $, startTime: et });
  }
  if (!j) throw new Error("Registration was not completed");
  const { id: tt, rawId: rt, response: nt, type: it } = j,
    ot = {
      id: tt,
      rawId: bufferToBase64URLString(rt),
      response: {
        attestationObject: bufferToBase64URLString(nt.attestationObject),
        clientDataJSON: bufferToBase64URLString(nt.clientDataJSON),
      },
      type: it,
      clientExtensionResults: j.getClientExtensionResults(),
      authenticatorAttachment: j.authenticatorAttachment,
    };
  return (
    typeof nt.getTransports == "function" &&
      (ot.transports = nt.getTransports()),
    ot
  );
}
const AUTHENTICATION_TIMEOUT = 6e4;
async function startAuthentication(o) {
  var st, ct;
  let _;
  ((st = o.allowCredentials) == null ? void 0 : st.length) !== 0 &&
    (_ =
      (ct = o.allowCredentials) == null
        ? void 0
        : ct.map(toPublicKeyCredentialDescriptor));
  const $ = {
      ...o,
      challenge: base64URLStringToBuffer(o.challenge),
      allowCredentials: _,
      timeout: AUTHENTICATION_TIMEOUT,
    },
    j = {};
  (j.publicKey = $), (j.signal = webauthnAbortService.createNewAbortSignal());
  let et;
  const tt = window.performance.now();
  try {
    et = await navigator.credentials.get(j);
  } catch (lt) {
    throw identifyAuthenticationError({ error: lt, options: j, startTime: tt });
  }
  if (!et) throw new Error("Authentication was not completed");
  const { id: rt, rawId: nt, response: it, type: ot } = et;
  let at;
  return (
    it.userHandle && (at = bufferToUTF8String(it.userHandle)),
    {
      id: rt,
      rawId: bufferToBase64URLString(nt),
      response: {
        authenticatorData: bufferToBase64URLString(it.authenticatorData),
        clientDataJSON: bufferToBase64URLString(it.clientDataJSON),
        signature: bufferToBase64URLString(it.signature),
        userHandle: at,
      },
      type: ot,
      clientExtensionResults: et.getClientExtensionResults(),
      authenticatorAttachment: et.authenticatorAttachment,
    }
  );
}
var WebAuthnErrorName = ((o) => (
  (o.AbortError = "AbortError"),
  (o.ConstraintError = "ConstraintError"),
  (o.InvalidStateError = "InvalidStateError"),
  (o.NotAllowedError = "NotAllowedError"),
  (o.NotSupportedError = "NotSupportedError"),
  (o.SecurityError = "SecurityError"),
  (o.TypeError = "TypeError"),
  (o.UnknownError = "UnknownError"),
  (o.NotRecognizedError = "NotRecognizedError"),
  (o.WebAuthnError = "WebAuthnError"),
  (o.TimeoutError = "TimeoutError"),
  (o.UserCanceled = "UserCanceled"),
  o
))(WebAuthnErrorName || {});
class WebAuthnError extends Error {
  constructor(_, $ = "WebAuthnError") {
    super(_), (this.name = $);
  }
}
function identifyAuthenticationError({ error: o, options: _, startTime: $ }) {
  var nt, it, ot, at;
  console.error("webauthn error:", o, _);
  const { publicKey: j } = _;
  if (!j) throw Error("options was missing required publicKey property");
  const et =
      (it = (nt = window.performance) == null ? void 0 : nt.now) == null
        ? void 0
        : it.call(nt),
    tt = !!($ && et - $ < 500),
    rt = !!($ && et - $ > AUTHENTICATION_TIMEOUT);
  if (o.name === "AbortError")
    return _.signal === new AbortController().signal
      ? new WebAuthnError(
          "Authentication ceremony was sent an abort signal",
          "AbortError"
        )
      : new WebAuthnError(
          "Authentication ceremony was aborted by the user agent",
          "NotSupportedError"
        );
  if (o.name === "NotReadableError")
    return new WebAuthnError(
      "User clicked cancel, or the authentication ceremony timed out",
      "NotAllowedError"
    );
  if (o.name === "NotAllowedError")
    return (ot = j.allowCredentials) != null && ot.length
      ? new WebAuthnError(
          "No available authenticator recognized any of the allowed credentials",
          "NotRecognizedError"
        )
      : (at = o == null ? void 0 : o.message) != null &&
        at.includes("cancelled")
      ? new WebAuthnError(
          "This request has been cancelled by the user.",
          "UserCanceled"
        )
      : tt
      ? new WebAuthnError(
          "Authentication ceremony was aborted by the user agent",
          "NotSupportedError"
        )
      : rt
      ? new WebAuthnError(
          "The Authentication ceremony timed out, please refresh this page try again",
          "TimeoutError"
        )
      : new WebAuthnError(
          "User clicked cancel, or the authentication ceremony timed out",
          "NotAllowedError"
        );
  if (o.name === "SecurityError") {
    const st = window.location.hostname;
    if (!isValidDomain(st))
      return new WebAuthnError(
        `${window.location.hostname} is an invalid domain`,
        "SecurityError"
      );
    if (j.rpId !== st)
      return new WebAuthnError(
        `The RP ID "${j.rpId}" is invalid for this domain`,
        "SecurityError"
      );
  } else {
    if (o.name === "UnknownError")
      return new WebAuthnError(
        "The authenticator was unable to process the specified options, or could not create a new assertion signature",
        "UnknownError"
      );
    if (o.message.includes("Not implemented"))
      return new WebAuthnError(
        "Authentication ceremony was aborted by the user agent",
        "NotSupportedError"
      );
  }
  return o;
}
function identifyRegistrationError({ error: o, options: _, startTime: $ }) {
  var nt, it, ot, at;
  console.error("webauthn error:", o, _);
  const { publicKey: j } = _,
    et =
      (it = (nt = window.performance) == null ? void 0 : nt.now) == null
        ? void 0
        : it.call(nt),
    tt = !!($ && et - $ < 500),
    rt = !!($ && et - $ > REGISTRATION_TIMEOUT);
  if (!j) throw Error("options was missing required publicKey property");
  if (o.name === "AbortError") {
    if (tt)
      return new WebAuthnError(
        "Registration ceremony was aborted by the user agent",
        "NotSupportedError"
      );
    if (_.signal === new AbortController().signal)
      return new WebAuthnError(
        "Registration ceremony was sent an abort signal",
        "AbortError"
      );
  } else {
    if (o.name === "NotReadableError")
      return new WebAuthnError(
        "User clicked cancel, or the registration ceremony timed out",
        "NotAllowedError"
      );
    if (o.name === "ConstraintError") {
      if (
        ((ot = j.authenticatorSelection) == null
          ? void 0
          : ot.requireResidentKey) === !0
      )
        return new WebAuthnError(
          "Discoverable credentials were required but no available authenticator supported it",
          "ConstraintError"
        );
      if (
        ((at = j.authenticatorSelection) == null
          ? void 0
          : at.userVerification) === "required"
      )
        return new WebAuthnError(
          "User verification was required but no available authenticator supported it",
          "ConstraintError"
        );
    } else {
      if (o.name === "InvalidStateError")
        return new WebAuthnError(
          "The authenticator was previously registered",
          "InvalidStateError"
        );
      if (o.name === "NotAllowedError")
        return tt
          ? new WebAuthnError(
              "Authentication ceremony was aborted by the user agent",
              "NotSupportedError"
            )
          : rt
          ? new WebAuthnError(
              "The registration ceremony timed out, please refresh this page try again",
              "TimeoutError"
            )
          : new WebAuthnError(
              "User clicked cancel, or the registration ceremony timed out",
              "NotAllowedError"
            );
      if (o.name === "NotSupportedError")
        return j.pubKeyCredParams.filter((ct) => ct.type === "public-key")
          .length === 0
          ? new WebAuthnError(
              'No entry in pubKeyCredParams was of type "public-key"',
              "NotSupportedError"
            )
          : new WebAuthnError(
              "No available authenticator supported any of the specified pubKeyCredParams algorithms",
              "NotSupportedError"
            );
      if (o.name === "SecurityError") {
        const st = window.location.hostname;
        if (!isValidDomain(st))
          return new WebAuthnError(
            `${window.location.hostname} is an invalid domain`,
            "SecurityError"
          );
        if (j.rp.id !== st)
          return new WebAuthnError(
            `The RP ID "${j.rp.id}" is invalid for this domain`,
            "SecurityError"
          );
      } else if (o.name === "TypeError") {
        if (j.user.id.byteLength < 1 || j.user.id.byteLength > 64)
          return new WebAuthnError(
            "User ID was not between 1 and 64 characters",
            "TypeError"
          );
      } else {
        if (o.name === "UnknownError")
          return new WebAuthnError(
            "The authenticator was unable to process the specified options, or could not create a new credential",
            "UnknownError"
          );
        if (o.message.includes("Not implemented"))
          return new WebAuthnError(
            "Registration ceremony was aborted by the user agent",
            "NotSupportedError"
          );
      }
    }
  }
  return o;
}
