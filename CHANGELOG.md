# @monocloud/authentication-api

## 0.1.3

### Patch Changes

- 2d568a7: - Added `DeleteAsync` to `IIntrospectionCache`, restoring the delete capability the interface family had
  before it was removed from the Node backend SDK; existing implementations must add the new member.
  - The SDK never calls it itself — it lets consumers evict a cached introspection entry before it expires
    (for example when a token is revoked), using a key produced by
    `MonoCloudAuthenticationOptions.CacheKeyGenerator`.
- 2d568a7: Rebuild the handler on top of ASP.NET Core's `JwtBearerHandler` instead of reimplementing the JWT path.

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

## 0.1.2

### Patch Changes

- 39dfa56: Use the issuer identifier as the JWT client assertion audience

## 0.1.1

### Patch Changes

- 002a9ef: Added spiffe auth and reviewed tests

## 0.1.0

### Minor Changes

- 1128b26: - Updated dependencies
- 1128b26: - Authentication API .NET SDK Initial Release
- 1128b26: - Rename the `IMonoCloudClaimsCache` interface to `IIntrospectionCache` and clarify that only introspection results are cached.
