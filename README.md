<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=backend_dotnet" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/backend-dotnet/refs/heads/main/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.nuget.org/packages/MonoCloud.Backend" target="_blank">
      <img src="https://img.shields.io/nuget/v/MonoCloud.Backend" alt="NuGet" />
    </a>
    <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/:license-MIT-blue.svg?style=flat" alt="License: MIT" />
    </a>
    <a href="https://github.com/monocloud/backend-dotnet/actions/workflows/build.yaml">
      <img src="https://github.com/monocloud/backend-dotnet/actions/workflows/build.yaml/badge.svg" alt="Build Status" />
    </a>
  </div>
</div>

## Introduction

**MonoCloud Backend SDK for .NET – secure access token validation for ASP.NET Core APIs and resource servers.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=backend_dotnet) is a modern, developer-friendly Identity & Access Management platform.

This SDK enables **ASP.NET Core APIs** to validate incoming access tokens issued by MonoCloud. It is implemented as a standard ASP.NET Core authentication handler, so it plugs directly into `AddAuthentication()`, `[Authorize]`, and the authorization policy system.

The SDK handles:

- **JWT access token validation** with signature and claims verification
- **Opaque token introspection** via the OpenID Connect introspection endpoint
- **Automatic token format detection** (JWT vs. opaque)
- **Scope and group-based authorization** through the standard policy system
- **Optional caching** of introspection results via `IIntrospectionCache`
- **mTLS certificate-bound token validation**
- **Multiple client authentication methods** for introspection: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, and `tls_client_auth`

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=backend_dotnet)
- **API Reference:** [https://monocloud.github.io/backend-dotnet](https://monocloud.github.io/backend-dotnet?utm_source=github&utm_medium=backend_dotnet)

## Supported Platforms

This SDK supports applications targeting **>= .NET 6.0**

## 🚀 Getting Started

### Requirements

- A **MonoCloud tenant**
- An **API identifier** (the audience for your API)
- For **opaque token introspection**: a **Client ID** and a client authentication method (e.g. a client secret)

### Installation

```powershell
Install-Package MonoCloud.Backend

# or

dotnet add package MonoCloud.Backend
```

### Usage

#### Validate JWT access tokens

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

#### Validate opaque tokens (introspection)

Opaque (reference) tokens are validated by calling the tenant's introspection endpoint. This requires a **Client ID** and a client authentication method:

```csharp
using MonoCloud.Backend;
using MonoCloud.Backend.Shared.ClientAuth;

builder.Services
    .AddAuthentication(MonoCloudAuthenticationDefaults.AuthenticationScheme)
    .AddMonoCloudAuthentication(options =>
    {
        options.TenantDomain = "https://<your-tenant-domain>";
        options.Audience = "<your-api-identifier>";
        options.ClientId = "<your-client-id>";
        options.ClientAuth = new ClientSecretAuth("<your-client-secret>");
    });
```

The handler **detects the token format automatically** — JWTs are validated locally against the tenant's signing keys, and opaque tokens are introspected. To force introspection even for JWTs, set `options.IntrospectJwtTokens = true`.

## When should I use `MonoCloud.Backend`?

Use **`MonoCloud.Backend`** if you are building an **ASP.NET Core API** that needs to validate access tokens from incoming requests.

This package is a good fit if you:

- Are building a **backend API** or **resource server** that accepts access tokens from clients or frontends
- Need to validate **JWT** or **opaque** access tokens
- Want **scope and group-based authorization** through the standard policy system
- Need to **validate certificate binding** for mTLS-protected tokens

> This SDK is for **API protection** (validating tokens). To **manage** your MonoCloud tenant programmatically (users, clients, groups, etc.), use [`MonoCloud.Management`](https://www.nuget.org/packages/MonoCloud.Management) instead.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=backend_dotnet)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/backend-dotnet/blob/main/LICENSE) file.
