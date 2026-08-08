---
'@monocloud/authentication-api': patch
---

Rebuild the handler on top of ASP.NET Core's `JwtBearerHandler` instead of reimplementing the JWT path.

- `MonoCloudAuthenticationOptions` now derives from `JwtBearerOptions` and `MonoCloudAuthenticationEvents`
  from `JwtBearerEvents`, so the familiar `AddJwtBearer` surface (`TokenValidationParameters`, `SaveToken`,
  `MapInboundClaims`, `OnTokenValidated`, `OnChallenge`, ...) applies to the MonoCloud scheme — and the
  standard events fire for opaque (introspected) tokens as well as JWTs.
- 401 responses now carry a standards-compliant RFC 6750
  `WWW-Authenticate: Bearer error="invalid_token", error_description="…"` challenge, gated by
  `IncludeErrorDetails`.
- Introspection, claims caching, mTLS certificate binding and client authentication are unchanged, and
  certificate binding is still enforced before the `TokenValidated` event on every path.
- The minimum supported framework is now **.NET 8.0**; the `net6.0` and `net7.0` targets were removed. The
  JwtBearer packages for those frameworks validate through `JwtSecurityTokenHandler` with no way to use
  `JsonWebTokenHandler`, which would have meant different JWT behaviour per target framework.
- `TenantDomain` was removed — set the inherited `Authority` to the tenant domain instead. A value without
  a scheme is prefixed with `https://`; an explicit `http://` is honoured (for development together with
  `RequireHttpsMetadata = false`, which now applies and defaults to `true`).
- `JwtTokenValidationParameters` was removed — use the inherited `TokenValidationParameters`.
- `SaveToken`, `RefreshOnIssuerKeyNotFound` and `IncludeErrorDetails` now default to `true`, matching
  `JwtBearerOptions`.
- The `MessageReceived`, `TokenValidated` and `AuthenticationFailed` events now use the framework's
  context types. `TokenValidatedContext.Token` (an `object`) is replaced by
  `TokenValidatedContext.SecurityToken`, which is `null` on the introspection path.
- A request without a bearer token now results in `AuthenticateResult.NoResult()` rather than a failure, so
  it stays anonymous and other schemes can run.
- On the JWT path the validated principal is left untouched unless a group claim actually needs
  flattening, so claim-type lookups are case-sensitive (`CaseSensitiveClaimsIdentity`) exactly as with
  `AddJwtBearer`; previously the SDK always rebuilt the identity with case-insensitive lookups.
