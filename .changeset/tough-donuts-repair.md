---
"@monocloud/authentication-api": patch
---

- Infrastructure failures during introspection (discovery, transport, non-2xx responses, malformed
  JSON, client auth) and exceptions from consumer event handlers on the opaque path now raise
  `AuthenticationFailed` with the real exception and rethrow (→ 500) instead of failing with a
  misleading 401 `invalid_token`. Token verdicts (`active:false`, certificate binding) still produce
  a 401. To restore the old behavior, handle `OnAuthenticationFailed` and set a `Result`.
- A failing introspection-cache write no longer fails an otherwise-successful authentication.
- A space-delimited `scope` claim in a locally validated JWT is split into one claim per scope,
  matching the introspection path, so `RequireClaim("scope", ...)` behaves identically on both paths.
- Claim normalization preserves the validated identity's type (Wilson 8's
  `CaseSensitiveClaimsIdentity` on .NET 9+) instead of rebuilding a case-insensitive `ClaimsIdentity`.
- The in-flight introspection de-duplication map is keyed by scheme + token, so concurrent
  introspections of the same token under different schemes no longer share a result.
- Removed `JwtAssertion.AssertionCacheExpiry` (compile-breaking if set): it was never honored — a
  fresh assertion (new `jti`) is generated for every introspection request.
