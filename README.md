<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=api_authentication_dotnet" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/api-authentication-dotnet/refs/heads/main/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.nuget.org/packages/MonoCloud.Authentication.Api" target="_blank">
      <img src="https://img.shields.io/nuget/v/MonoCloud.Authentication.Api" alt="NuGet" />
    </a>
    <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/:license-MIT-blue.svg?style=flat" alt="License: MIT" />
    </a>
    <a href="https://github.com/monocloud/api-authentication-dotnet/actions/workflows/build.yaml">
      <img src="https://github.com/monocloud/api-authentication-dotnet/actions/workflows/build.yaml/badge.svg" alt="Build Status" />
    </a>
  </div>
</div>

## Introduction

**MonoCloud Api Authentication SDK for .NET – secure access token validation for ASP.NET Core APIs and resource servers.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=api_authentication_dotnet) is a modern, developer-friendly Identity & Access Management platform.

This SDK enables **ASP.NET Core APIs** to validate incoming access tokens issued by MonoCloud. It is implemented as a standard ASP.NET Core authentication handler, so it plugs directly into `AddAuthentication()`, `[Authorize]`, and the authorization policy system.

The SDK handles:

- **JWT access token validation** with signature and claims verification
- **Opaque token introspection** via the OpenID Connect introspection endpoint
- **Automatic token format detection** (JWT vs. opaque)
- **Scope and group-based authorization** through the standard policy system
- **Optional caching** of introspection results via `IIntrospectionCache`
- **mTLS certificate-bound token validation**
- **Multiple client authentication methods** for introspection

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=api_authentication_dotnet)
- **Quickstart:** [https://www.monocloud.com/docs/quickstarts/dotnet-api-authentication](https://www.monocloud.com/docs/quickstarts/dotnet-api-authentication?utm_source=github&utm_medium=api_authentication_dotnet)
- **SDK Reference:** [https://www.monocloud.com/docs/sdks/dotnet-api-authentication](https://www.monocloud.com/docs/sdks/dotnet-api-authentication?utm_source=github&utm_medium=api_authentication_dotnet)
- **API Reference:** [https://monocloud.github.io/api-authentication-dotnet](https://monocloud.github.io/api-authentication-dotnet?utm_source=github&utm_medium=api_authentication_dotnet)

## Supported Platforms

This SDK supports applications targeting **>= .NET 8.0**

## 🚀 Getting Started

### Requirements

- A **MonoCloud tenant**
- An **API identifier** (the audience for your API)
- For **opaque token introspection**: a **Client ID** and a **client secret**

### Installation

```powershell
Install-Package MonoCloud.Authentication.Api

# or

dotnet add package MonoCloud.Authentication.Api
```

### Usage

#### Validate JWT access tokens

```csharp
using System.Security.Claims;
using MonoCloud.Authentication.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(MonoCloudAuthenticationDefaults.AuthenticationScheme)
    .AddMonoCloudAuthentication(options =>
    {
        options.Authority = "https://<your-tenant-domain>";
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
builder.Services
    .AddAuthentication(MonoCloudAuthenticationDefaults.AuthenticationScheme)
    .AddMonoCloudAuthentication(options =>
    {
        options.Authority = "https://<your-tenant-domain>";
        options.Audience = "<your-api-identifier>";
        options.ClientId = "<your-client-id>";
        options.ClientAuth = new ClientSecretAuth("<your-client-secret>");
    });
```

The handler **detects the token format automatically** — JWTs are validated locally against the tenant's signing keys, and opaque tokens are introspected. To force introspection even for JWTs, set `options.IntrospectJwtTokens = true`.

## When should I use `MonoCloud.Authentication.Api`?

Use **`MonoCloud.Authentication.Api`** if you are building an **ASP.NET Core API** that needs to validate access tokens from incoming requests.

This package is a good fit if you:

- Are building **applications or microservices** that accept access tokens from clients or frontends
- Need to validate **JWT** or **opaque** access tokens
- Want **scope and group-based authorization** through the standard policy system
- Need to **validate certificate binding** for mTLS-protected tokens

> This SDK is for **API protection** (validating tokens). To **manage** your MonoCloud tenant programmatically (users, clients, groups, etc.), use [`MonoCloud.Management`](https://www.nuget.org/packages/MonoCloud.Management) instead.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=api_authentication_dotnet)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/api-authentication-dotnet/blob/main/LICENSE) file.
