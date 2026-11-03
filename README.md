# Davids.Shared

| Pull Request CI | CodeQL SAST | Platform Architecture & Orchestration |
|---|---|---|
| [![Pull Request CI — Security Gate](https://github.com/dav-Ste/Davids.Shared/actions/workflows/pull-request-ci.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Shared/actions/workflows/pull-request-ci.yml) | [![Pull Request CI — CodeQL SAST](https://github.com/dav-Ste/Davids.Shared/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Shared/actions/workflows/codeql.yml) | [**`Davids` — Architecture & Security Diagram**](https://github.com/dav-Ste/Davids#architecture-project-relationships--security-posture) |

`Davids.Shared` is the standalone `.NET 10` shared library repository (`Davids.Shared.slnx`) hosting `Davids.ServiceDefaults` — the cross-cutting host defaults (health/liveness endpoints, OpenTelemetry metrics/tracing/logging exporters, `Davids.Security.Audit` security telemetry counters, hardened `ForwardedHeadersMiddleware`, isolated AES-256-GCM / X.509 ASP.NET Core Data Protection encryption-at-rest, `Microsoft.Extensions.ServiceDiscovery`, and optional Serilog sinks) shared across all five Davids runtime services and frontends.

Separating `Davids.ServiceDefaults` into `Davids.Shared` allows any individual microservice repository (`Davids.Services.Customers`, `Davids.Services.Identity`, `Davids.Services.AdminIdentity`, `Davids.APIGateway`, or `Davids.Frontend.Admin`) to be cloned beside `Davids.Shared` and built, tested, and run standalone **without** cloning the `Davids` Aspire infrastructure repository.

## Standalone service layout

To work on a single service without the full Aspire stack, clone only `Davids.Shared` and that service into the same parent directory:

```text
<workspace>/
  Davids.Shared/                # this repository (Davids.ServiceDefaults + eng/Davids.Common.props)
  Davids.Services.Customers/    # e.g., build, test & run Customers API standalone
```

## Projects & shared engineering configuration

- `eng/Davids.Common.props`: Centralized MSBuild baseline (`net10.0`, `<Nullable>enable</Nullable>`, `<UseArtifactsOutput>true</UseArtifactsOutput>` routing build/intermediate/publish outputs to `<RepoRoot>/artifacts/`, `TreatWarningsAsErrors`, `NuGetAudit` with `NU1900`–`NU1904` as errors, `AnalysisModeSecurity=All`, and `RestorePackagesWithLockFile=true`) imported by `Directory.Build.props` across all 7 repositories.
- `src/Davids.ServiceDefaults`: `AddServiceDefaults(...)`, `DavidsSecurityContracts` (`WorkforceRoles`, `VerifiedActorHeaders`, `ChangeAuditDiffBuilder`), `DavidsSecurityMetrics` (`Davids.Security.Audit` meter including `davids.security.change_audit`), `AesGcmDataProtectionXmlEncryptor`, trusted CIDR/IP `ForwardedHeadersMiddleware`, and `MapDefaultEndpoints()` (`/health` and `/alive`).
- `tests/Davids.ServiceDefaults.Tests`: Unit, architecture, and in-memory `TestServer` verification (`[Trait("Category", "Unit" | "Integration")]`) for OpenTelemetry exporters, Data Protection encryption-at-rest, health probes, and fail-closed sink validation.

## Build, test & NuGet package mode (`UseSharedPackageReference`)

```powershell
dotnet restore Davids.Shared.slnx --locked-mode
dotnet build Davids.Shared.slnx --no-restore -c Release -warnaserror
dotnet test Davids.Shared.slnx --no-build --no-restore -c Release
```

All 5 consumer repositories (`Davids.Services.Identity`, `Davids.Services.AdminIdentity`, `Davids.Services.Customers`, `Davids.APIGateway`, and `Davids.Frontend.Admin`) support switching seamlessly between a local sibling `<ProjectReference>` (default when `../Davids.Shared` is checked out) and a versioned NuGet `<PackageReference Include="Davids.ServiceDefaults" />`:

- **Pack `Davids.ServiceDefaults` (`artifacts/package/release/Davids.ServiceDefaults.1.0.0.nupkg`)**:
  ```powershell
  ./scripts/Pack-SharedPackages.ps1 -Version 1.0.0
  ```
- **Build or test any consumer service against the NuGet package** (activated explicitly via `/p:UseSharedPackageReference=true`, or automatically whenever `../Davids.Shared` is not checked out alongside the repository):
  ```powershell
  dotnet test ../Davids.Services.Customers/tests/Davids.Services.Customers.Tests/Davids.Services.Customers.Tests.csproj `
    -c Release -warnaserror `
    /p:UseSharedPackageReference=true `
    /p:RestoreAdditionalProjectSources="$PWD/artifacts/package/release"
  ```

## Related repositories

- [`Davids`](https://github.com/dav-Ste/Davids) — `.NET 10` Aspire AppHost, Vault bootstrap, Kubernetes/Istio manifests, architecture diagram & lifecycle security suite
- [`Davids.APIGateway`](https://github.com/dav-Ste/Davids.APIGateway) — YARP `2.3.0` edge reverse proxy & confidential Admin OIDC BFF
- [`Davids.Services.Identity`](https://github.com/dav-Ste/Davids.Services.Identity) — Customer OpenIddict `RS256` OIDC Provider (`identitydb`)
- [`Davids.Services.AdminIdentity`](https://github.com/dav-Ste/Davids.Services.AdminIdentity) — Administrator OpenIddict `RS256` OIDC Provider (`adminidentitydb`)
- [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers) — Customer profiles & order tracking API (`customersdb`)
- [`Davids.Frontend.Admin`](https://github.com/dav-Ste/Davids.Frontend.Admin) — Passwordless Workforce RBAC customer, IAM & audit web UI
- [`Davids.Frontend.Web`](https://github.com/dav-Ste/Davids.Frontend.Web) — Customer Self-Service Web Portal (`CustomerBffCookie` PKCE `S256` BFF)
