# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

**MonoCloud.Authentication.Api** — the MonoCloud authentication SDK for ASP.NET Core APIs / resource servers.
It is a standard ASP.NET Core **authentication handler** that validates incoming MonoCloud
access tokens. It plugs into `AddAuthentication()`, `[Authorize]`, and the authorization
policy system.

Capabilities:
- JWT access-token validation (signature + claims) against the tenant's signing keys.
- Opaque/reference token introspection (RFC 7662), with automatic JWT-vs-opaque detection.
- Scope and group based authorization via the standard policy system.
- Optional caching of introspection results via `IIntrospectionCache`.
- mTLS certificate-bound access tokens (RFC 8705) — `cnf`/`x5t#S256` validation.
- Client authentication for introspection: `client_secret_basic`, `client_secret_post`,
  `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `spiffe_jwt` (JWT-SVID forwarded as a
  client assertion), and `spiffe_x509` (X.509-SVID over mTLS; behaves like `tls_client_auth`).

Repo conventions mirror the sibling `management-dotnet` SDK. There are three intentional, distinct
naming axes: the public package id / assembly / root namespace / project folder / solution file are
all `MonoCloud.Authentication.Api`; the GitHub repository is `monocloud/api-authentication-dotnet`;
and the Changesets/npm tooling name in `package.json` is `@monocloud/authentication-api`.

## Layout

```
MonoCloud.Authentication.Api/                      # the library (multi-targeted)
  MonoCloudAuthenticationHandler.cs     # core: HandleAuthenticateAsync, JWT + opaque paths, cert binding, introspection
  MonoCloudAuthenticationOptions.cs     # all configurable options (AuthenticationSchemeOptions)
  MonoCloudAuthenticationExtension.cs   # AddMonoCloudAuthentication(...) DI entry points
  PostConfigureMonoCloudAuthenticationOptions.cs  # fills in HttpClient / ConfigurationManager / defaults
  MonoCloudAuthenticationEvents.cs      # extensibility hooks (OnTokenValidated, OnIntrospection, etc.)
  MonoCloudAuthenticationDefaults.cs    # scheme name + http client name constants
  Shared/
    Utils.cs                            # cache get/set, cache-key gen, NormalizeGroupClaims, exp/TTL logic
    ClaimConverter.cs                   # System.Text.Json converter for Claim (Type+Value only)
    IntrospectionResult.cs              # parses RFC 7662 JSON -> claims + IsActive
    IIntrospectionCache.cs              # the caching abstraction consumers implement
    JwtAssertion.cs / MtlsEndpointAliases.cs
    ClientAuth/                         # ClientSecretAuth, JwtAssertionAuth, TlsAuth, SpiffeJwtAuth, SpiffeX509Auth (: TlsAuth), IMonoCloudClientAuth, ClientAuthenticationContext
    Context/                            # event context types (ResultContext<MonoCloudAuthenticationOptions> subclasses)
  GlobalUsings.cs                       # explicit global imports (implicit usings are off — see Conventions)
  MonoCloud.Authentication.Api.csproj              # multi-target TFMs, packaging, InternalsVisibleTo, SourceLink
  README.nuget.md                       # readme packed into the NuGet package
MonoCloud.Authentication.Api.Tests/                # NUnit + Moq + Shouldly tests, Mocks/, Helpers/HandlerTestHarness, OpenIdServerMock
MonoCloud.Authentication.Api.slnx                  # solution (new XML slnx format)
Directory.Packages.props                # central package versions + shared build props (nullable, langversion, signing)
global.json                             # pins .NET SDK 10 (rollForward latestMajor)
.editorconfig                           # formatting + analyzer rules (source of truth for style)
.config/dotnet-tools.json               # local dotnet tool manifest (reportgenerator, used by `pnpm test` coverage HTML)
.github/workflows/                      # CI: build.yaml (build+lint+test, uploads .trx), test-report.yaml (workflow_run reporter), release.yaml (changeset release PR), nuget-publish.yaml (release + !snapshot, OIDC trusted publishing)
package.json                            # Node toolchain: pnpm, Changesets versioning, gen:docs (docfx), test+coverage
docs-gen/                               # docfx site source (docfx.json/index.md/toc.yml); built via `pnpm gen:docs`
```

## Build & test

The library multi-targets **net6.0; net7.0; net8.0; net9.0; net10.0**. The test project targets **net10.0**.

```bash
dotnet build MonoCloud.Authentication.Api.slnx
dotnet test  MonoCloud.Authentication.Api.slnx                 # all tests
dotnet test  MonoCloud.Authentication.Api.slnx --filter "FullyQualifiedName~CertificateBinding"   # subset
```

Requires the .NET 10 SDK (see `global.json`). The test framework is **NUnit 4** with **Moq** and
**Shouldly** assertions. The library exposes internals to the test project via `InternalsVisibleTo`.

A **Node toolchain** wraps the .NET build for repo tasks (managed with **pnpm**, see `package.json`):

```bash
pnpm test          # rimraf TestResults/CoverageReport, dotnet test with XPlat coverage, then HTML report -> CoverageReport/
pnpm gen:docs      # build the docfx site from docs-gen/
pnpm changeset     # record a version bump (Changesets; .changeset/, baseBranch main)
```

**CI** lives in `.github/workflows/` and mirrors the `auth-js` repo's patterns:

- `build.yaml` (**Build & Test**) runs on push/PR to `main` as three jobs: `build`, `lint-dotnet`
  (`dotnet format --verify-no-changes`), and `test`. It runs `dotnet test` directly (no `pnpm test` in
  CI) and only **uploads** the `.trx` as an artifact — it does not post the check, and holds
  `contents: read` only, so it works for fork PRs.
- `test-report.yaml` runs on **`workflow_run`** after Build & Test, in the trusted base-repo context
  (`checks: write` + `pull-requests: write`), downloads that artifact and posts the test report — so
  results show on **fork PRs** too. It never checks out PR code.
- `release.yaml` (**Release PRs**) opens the Changesets release PR (branch `changeset-release/main`),
  running `.github/scripts/update-version.sh` to bump the version and sync `<Version>` in
  `Directory.Packages.props`.
- `nuget-publish.yaml` is the single workflow that pushes to **nuget.org via Trusted Publishing
  (OIDC)** — both the stable release (on merge of `changeset-release/main`) and the `!snapshot` canary
  live in that one file, because nuget.org's trusted-publishing policy is bound to one workflow
  filename and validates the file where `NuGet/login` runs (so the login+push steps must not move to a
  reusable workflow). The `!snapshot` path **refuses forks** (head repo must equal base repo) and
  requires the commenter to have **write access** (`getCollaboratorPermissionLevel`), so untrusted
  fork code never runs in the job that holds `id-token: write` — there is no GitHub Environment gate.
  Publishing needs the `NUGET_USER` secret (nuget.org profile name); there is no long-lived NuGet API
  key. The fork guard and release `if` pin to `github.repository == 'monocloud/api-authentication-dotnet'`.

## Conventions

- **Central package management**: versions live in `Directory.Packages.props` (`<PackageVersion>`),
  project files use bare `<PackageReference Include="..." />` with no version. The JwtBearer
  package version is selected per target framework there. Add/upgrade packages there, not in csproj.
- `<Nullable>enable</Nullable>` is on for all projects (set in `Directory.Packages.props`); honor
  nullability annotations. `<ImplicitUsings>` is **not declared anywhere** (there is no
  `Directory.Build.props`), so implicit usings are off — each project lists its common imports
  explicitly in a `GlobalUsings.cs` — add shared namespaces (including BCL ones like `System`,
  `System.Threading.Tasks`) there rather than per-file. The test project sets
  `GenerateDocumentationFile=false` to opt out of the repo-wide doc generation (no CS1591 on test members).
- Assemblies are strong-named (`SignAssembly`); reproducible builds + SourceLink are enabled.
- Multi-targeting matters: code in the library must compile on net6.0 through net10.0. The handler
  has `#if NET8_0_OR_GREATER` constructor branches for the `ISystemClock`/`TimeProvider` change —
  preserve both branches when touching the constructor.
- Two-space indentation in C# files. Formatting/analyzer rules are governed by the repo
  `.editorconfig` (run `dotnet format` to apply).

## Architecture notes (how a request is authenticated)

1. `HandleAuthenticateAsync` raises `MessageReceived`, then pulls the bearer token from the
   `Authorization` header if the event didn't supply one.
2. Routing: if `!IntrospectJwtTokens` and the token parses as a JWT, it goes to the **JWT path**
   (local validation via `JwtTokenHandler` against discovery signing keys + configured params);
   otherwise the **opaque path** (RFC 7662 introspection).
3. Opaque path: optional read-through of `IIntrospectionCache` (gated by `EnableCaching`; key = `CacheKeyPrefix` + SHA-256 of
   `schemeName|token`, so the same token doesn't collide across schemes); otherwise
   introspect (client auth applied per `Options.ClientAuth`), cache the result, build the principal.
   In-flight introspections for the same token string are de-duplicated via a static `IntrospectionCache`
   (`ConcurrentDictionary` of `Lazy<Task<IntrospectionResult>>`) removed in a `finally` — this only
   collapses concurrent duplicate calls, it is not a result cache.
4. If `ValidateCertificateBinding(context)` returns true, the presented client certificate's
   base64url SHA-256 is compared against the token's `cnf.x5t#S256` claim — enforced on the JWT path,
   the live opaque path, and the cached opaque path.
5. `PostConfigure` runs once per options instance: https-prefixes `TenantDomain`, copies `Audience`
   into `ValidAudience`, builds the `HttpClient` (special-cased for `TlsAuth` with a client cert),
   and builds the `ConfigurationManager` (static if `Configuration` set, else discovery from the
   tenant `.well-known/openid-configuration`).

## Gotchas / non-obvious behavior

- **`MapInboundClaims` defaults to `true`** and is applied to the internal `JsonWebTokenHandler` in the
  `MonoCloudAuthenticationOptions` constructor. The field initializer alone does NOT reach the handler
  (its instance default is `false`), so the ctor and the property setter must keep them in sync — don't
  drop that sync. With it on, JWT claim types map to legacy WS-* URIs (e.g. `sub` → `…/nameidentifier`)
  unless a consumer sets `MapInboundClaims = false`.
- **`IIntrospectionCache` must be registered as a singleton.** The `IPostConfigureOptions`
  implementation that checks for it is itself a singleton, so a scoped registration fails DI scope
  validation. This requirement is documented on the interface.
- **Claims-cache key** includes the authentication scheme name (assigned to `options.SchemeName` during
  post-configuration), not just the token — keep that discriminator in `Utils.CacheKeyGenerator` or
  multi-scheme deployments will share cache entries.
- **`IntrospectionResult` parsing is deliberately lenient about odd response shapes**: a non-string
  `iss` and non-string/`null` elements inside a `scope` array are skipped rather than thrown on (a throw
  there would reject an otherwise-valid token). The `exp` parse in `Utils` likewise never throws — a
  missing/non-numeric `exp` just falls back to caching for the configured duration.
- **`cnf` is parsed as `Dictionary<string, JsonElement>`** and only `x5t#S256` is read, so a `cnf`
  carrying extra members (e.g. a `jwk`) still validates. The thumbprint comparison uses
  `CryptographicOperations.FixedTimeEquals` — keep it.
- **Known limitation (intentional):** the in-flight `IntrospectionCache` is keyed by the raw token only
  (no scheme discriminator), unlike the persisted introspection cache.

## Working norms

- **Do not commit or push without explicit approval.** The maintainer reviews diffs against the
  prior code before any commit. Make changes in the working tree and stop.
- This is security-sensitive auth code. Prefer minimal, surgical changes; preserve existing behavior
  on all target frameworks. When changing token-validation, caching, or certificate-binding logic,
  add or update tests in `MonoCloud.Authentication.Api.Tests`.
