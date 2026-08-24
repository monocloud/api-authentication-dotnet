---
'@monocloud/authentication-api': patch
---

Add certificate binding validation modes.

- `ValidateCertificateBinding` is now a `CertificateBindingValidation` enum instead of a `Func<HttpContext, bool>`.
- Tokens whose `cnf` (confirmation) claim carries an `x5t#S256` thumbprint are now validated by default; previously the default never validated. Replace `ValidateCertificateBinding = _ => true` with `CertificateBindingValidation.Required`, and set `CertificateBindingValidation.DangerouslyIgnore` to opt out entirely.
- A `CertificateRetriever` that throws now fails authentication with a 401 `invalid_token` challenge (`Client certificate is malformed`) instead of surfacing a 500.
