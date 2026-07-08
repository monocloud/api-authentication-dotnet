![MonoCloud Banner](https://raw.githubusercontent.com/monocloud/backend-dotnet/refs/heads/main/banner.svg)

## Introduction

**MonoCloud Backend SDK for .NET – secure access token validation for ASP.NET Core APIs and resource servers.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=backend_dotnet) is a modern, developer-friendly Identity & Access Management platform.

This SDK enables **ASP.NET Core APIs** to validate incoming access tokens issued by MonoCloud. It is implemented as a standard ASP.NET Core authentication handler, so it plugs directly into `AddAuthentication()`, `[Authorize]`, and the authorization policy system.

The SDK handles:

- **JWT access token validation** with signature and claims verification
- **Opaque token introspection** (RFC 7662) with automatic JWT vs. opaque detection
- **Scope and group-based authorization** through the standard policy system
- **Optional caching** of introspection results via `IIntrospectionCache`
- **mTLS certificate-bound token validation** (RFC 8705)
- **Multiple client authentication methods** for introspection: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, and `tls_client_auth`

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=backend_dotnet)
- **API Reference:** [https://monocloud.github.io/backend-dotnet](https://monocloud.github.io/backend-dotnet?utm_source=github&utm_medium=backend_dotnet)

## Supported Platforms

This SDK supports applications targeting **>= .NET 6.0**

## 📦 Installation

```powershell
dotnet add package MonoCloud.Backend
```

## Usage

```csharp
using System.Security.Claims;
using MonoCloud.Backend;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(MonoCloudAuthenticationDefaults.AuthenticationScheme)
    .AddMonoCloudAuthentication(options =>
    {
        options.TenantDomain = "https://<your-tenant-domain>";
        options.Audience = "<your-api-identifier>";

        // Required only for opaque (reference) token introspection:
        // options.ClientId = "<your-client-id>";
        // options.ClientAuth = new ClientSecretAuth("<your-client-secret>");
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/protected", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name}")
   .RequireAuthorization();

app.Run();
```

> [!CAUTION]
> Do not hardcode secrets. Load the tenant domain, client id, and client secret from environment variables, `appsettings.json`, or a secure secret store.

The handler detects the token format automatically — JWTs are validated locally against the tenant's signing keys, and opaque tokens are introspected.

For full usage (scope/group authorization, client authentication methods, claims caching, mTLS certificate binding, and events), see the [documentation](https://www.monocloud.com/docs?utm_source=github&utm_medium=backend_dotnet) and the [GitHub repository](https://github.com/monocloud/backend-dotnet).

## 📄 License

Licensed under the **MIT License**.
