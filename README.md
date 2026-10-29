# Davids.Shared

`Davids.Shared` is the standalone .NET 10 shared library repository (`Davids.Shared.slnx`) hosting `Davids.ServiceDefaults` — the lightweight cross-cutting host defaults (health/liveness endpoints, OpenTelemetry metrics/tracing/logging exporters, `Microsoft.Extensions.ServiceDiscovery`, and optional Serilog sinks) shared across all Davids microservices and frontends.

Separating `Davids.ServiceDefaults` into `Davids.Shared` allows any individual microservice repository (`Davids.Services.Customers`, `Davids.Services.Identity`, `Davids.Services.AdminIdentity`, `Davids.APIGateway`, or `Davids.Frontend.Admin`) to be cloned beside `Davids.Shared` and built, tested, and run standalone **without** cloning the `Davids` Aspire infrastructure repository.

## Standalone service layout

To work on a single service without the full Aspire stack, clone only `Davids.Shared` and that service into the same parent directory:

```text
<workspace>/
  Davids.Shared/                # this repository (Davids.ServiceDefaults)
  Davids.Services.Customers/    # e.g., build & run Customers API standalone
```

## Projects & Shared Engineering Configuration

- `eng/Davids.Common.props`: Centralized MSBuild baseline (`net10.0`, `<UseArtifactsOutput>true</UseArtifactsOutput>` routing build/intermediate/publish outputs to `<RepoRoot>/artifacts/`, `TreatWarningsAsErrors`, `NuGetAudit` with `NU1900`–`NU1904` as errors, `AnalysisModeSecurity=All`, and `RestorePackagesWithLockFile=true`) imported by `Directory.Build.props` across all 7 repositories.
- `src/Davids.ServiceDefaults`: `AddServiceDefaults(...)` and `MapDefaultEndpoints()` (`/health` and `/alive`) using built-in ASP.NET Core, OpenTelemetry, ServiceDiscovery, and optional Serilog sinks.
- `tests/Davids.ServiceDefaults.Tests`: unit and in-memory `TestServer` verification for OpenTelemetry exporters, health probes, and fail-closed sink validation.

## Build, Test & NuGet Package Mode (`UseSharedPackageReference`)

```powershell
dotnet restore Davids.Shared.slnx --locked-mode
dotnet build Davids.Shared.slnx --no-restore -c Release
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
