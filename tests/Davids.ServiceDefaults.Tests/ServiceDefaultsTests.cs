using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Xunit;

namespace Davids.ServiceDefaults.Tests;

public sealed class ServiceDefaultsTests
{
    [Fact]
    [Trait("Category", "Unit")]
    public void ServiceDefaultsConfigureOpenTelemetryExportersWhenEnabled()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://localhost:1";
        builder.Configuration["Telemetry:Jaeger:Enabled"] = "true";
        builder.Configuration["Telemetry:Jaeger:Endpoint"] = "http://localhost:2/v1/traces";
        builder.Configuration["Telemetry:Prometheus:Enabled"] = "true";
        builder.Configuration["Telemetry:Prometheus:Endpoint"] = "http://localhost:3/api/v1/otlp/v1/metrics";
        builder.Configuration["Telemetry:InfluxDB:Enabled"] = "true";
        builder.Configuration["Telemetry:InfluxDB:Endpoint"] = "http://localhost:4/v1/metrics";

        builder.AddServiceDefaults("davids-shared-test");
        using var host = builder.Build();

        Assert.NotNull(host.Services.GetRequiredService<TracerProvider>());
        Assert.NotNull(host.Services.GetRequiredService<MeterProvider>());
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task MapDefaultEndpointsExposesAnonymousHealthAndAliveProbes()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.AddServiceDefaults("davids-shared-test");

        await using var app = builder.Build();
        app.MapDefaultEndpoints();
        await app.StartAsync();

        using var client = app.GetTestClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/alive")).StatusCode);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void ExternalLoggingFailsClosedWhenSinkEnabledWithoutUrl()
    {
        var seqBuilder = Host.CreateApplicationBuilder();
        seqBuilder.Configuration["LoggingSinks:Seq:Enabled"] = "true";
        Assert.Throws<InvalidOperationException>(() => seqBuilder.AddServiceDefaults("davids-shared-test"));

        var elasticBuilder = Host.CreateApplicationBuilder();
        elasticBuilder.Configuration["LoggingSinks:Elasticsearch:Enabled"] = "true";
        Assert.Throws<InvalidOperationException>(() => elasticBuilder.AddServiceDefaults("davids-shared-test"));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task TrustedForwardedHeadersAcceptKnownProxyCidrAndRejectUntrustedSpoofing()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = "Production";
        builder.WebHost.UseTestServer();
        builder.Configuration["ForwardedHeaders:KnownNetworks:0"] = "10.244.0.0/16";
        builder.Services.AddTrustedForwardedHeaders(builder.Configuration, builder.Environment, trustLoopbackInNonProduction: false);

        await using var app = builder.Build();
        app.UseTrustedForwardedHeaders();
        app.MapGet("/ip", (Microsoft.AspNetCore.Http.HttpContext ctx) =>
            Microsoft.AspNetCore.Http.Results.Text(ctx.Connection.RemoteIpAddress?.ToString() ?? "none"));
        await app.StartAsync();

        var server = app.GetTestServer();

        // Request from trusted cluster proxy CIDR 10.244.1.25 rewrites RemoteIpAddress to client IP 198.51.100.42.
        var trustedCtx = await server.SendAsync(ctx =>
        {
            ctx.Connection.RemoteIpAddress = IPAddress.Parse("10.244.1.25");
            ctx.Request.Method = "GET";
            ctx.Request.Path = "/ip";
            ctx.Request.Headers["X-Forwarded-For"] = "198.51.100.42";
        });
        Assert.Equal("198.51.100.42", await new StreamReader(trustedCtx.Response.Body).ReadToEndAsync());

        // Request from untrusted peer 203.0.113.77 attempting to spoof X-Forwarded-For is ignored.
        var spoofCtx = await server.SendAsync(ctx =>
        {
            ctx.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.77");
            ctx.Request.Method = "GET";
            ctx.Request.Path = "/ip";
            ctx.Request.Headers["X-Forwarded-For"] = "198.51.100.42";
        });
        Assert.Equal("203.0.113.77", await new StreamReader(spoofCtx.Response.Body).ReadToEndAsync());

        // When zero proxies/networks are configured (e.g. internet-facing Gateway without an external ingress proxy),
        // ForwardedHeaders must NOT fall back to ASP.NET Core's empty-allowlist "trust everyone" behavior.
        var noProxyBuilder = WebApplication.CreateBuilder();
        noProxyBuilder.Environment.EnvironmentName = "Production";
        noProxyBuilder.WebHost.UseTestServer();
        noProxyBuilder.Services.AddTrustedForwardedHeaders(
            noProxyBuilder.Configuration,
            noProxyBuilder.Environment,
            trustLoopbackInNonProduction: false);
        await using var noProxyApp = noProxyBuilder.Build();
        noProxyApp.UseTrustedForwardedHeaders();
        noProxyApp.MapGet("/ip", (Microsoft.AspNetCore.Http.HttpContext ctx) =>
            Microsoft.AspNetCore.Http.Results.Text(ctx.Connection.RemoteIpAddress?.ToString() ?? "none"));
        await noProxyApp.StartAsync();

        var directSpoofCtx = await noProxyApp.GetTestServer().SendAsync(ctx =>
        {
            ctx.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.10");
            ctx.Request.Method = "GET";
            ctx.Request.Path = "/ip";
            ctx.Request.Headers["X-Forwarded-For"] = "10.0.0.99";
        });
        Assert.Equal("198.51.100.10", await new StreamReader(directSpoofCtx.Response.Body).ReadToEndAsync());
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TrustedForwardedHeadersFailClosedOnMalformedProxyOrCidr()
    {
        var badProxy = WebApplication.CreateBuilder();
        badProxy.Configuration["ForwardedHeaders:KnownProxies:0"] = "not-an-ip";
        Assert.Throws<InvalidOperationException>(() =>
            badProxy.Services.AddTrustedForwardedHeaders(badProxy.Configuration, badProxy.Environment));

        var badCidr = WebApplication.CreateBuilder();
        badCidr.Configuration["ForwardedHeaders:KnownNetworks:0"] = "10.0.0.0/99";
        Assert.Throws<InvalidOperationException>(() =>
            badCidr.Services.AddTrustedForwardedHeaders(badCidr.Configuration, badCidr.Environment));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void DataProtectionEncryptsKeyRingWithAesGcmEnforcesServiceAadIsolationAndSupportsX509()
    {
        var sharedStore = new List<System.Xml.Linq.XElement>();
        var repo = new InMemoryXmlRepository(sharedStore);
        const string masterKey = "0123456789abcdef0123456789abcdef-master-wrapping-key!";

        static ServiceProvider BuildProvider(
            Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository xmlRepo,
            string appName,
            string? key,
            string envName = "Production")
        {
            var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = envName });
            if (key is not null)
            {
                builder.Configuration["DataProtection:MasterKey"] = key;
            }

            Microsoft.Extensions.DependencyInjection.DataProtectionServiceCollectionExtensions
                .AddDataProtection(builder.Services)
                .ConfigureDavidsDataProtection(
                    builder.Configuration,
                    builder.Environment,
                    applicationName: appName,
                    externalRepositoryFactory: _ => xmlRepo);
            return builder.Services.BuildServiceProvider();
        }

        string ciphertext;
        using (var replicaA = BuildProvider(repo, "davids-api-gateway", masterKey))
        {
            var protectorA = replicaA.GetRequiredService<IDataProtectionProvider>().CreateProtector("bff.cookie.v1");
            ciphertext = protectorA.Protect("admin-session-payload");
        }

        // Verify stored XML is AES-256-GCM encrypted at rest (zero plaintext <masterKey> material).
        Assert.NotEmpty(sharedStore);
        var storedXml = sharedStore.Single().ToString();
        Assert.Contains("encryptedKey", storedXml, StringComparison.Ordinal);
        Assert.DoesNotContain("<masterKey", storedXml, StringComparison.OrdinalIgnoreCase);

        // Replica B with identical applicationName + MasterKey decrypts seamlessly across restarts/pods.
        using (var replicaB = BuildProvider(repo, "davids-api-gateway", masterKey))
        {
            var protectorB = replicaB.GetRequiredService<IDataProtectionProvider>().CreateProtector("bff.cookie.v1");
            Assert.Equal("admin-session-payload", protectorB.Unprotect(ciphertext));
        }

        // Cross-service AAD isolation: another service cannot unwrap davids-api-gateway's key ring even if given the same string.
        using (var wrongService = BuildProvider(repo, "davids-identity", masterKey))
        {
            var protectorWrong = wrongService.GetRequiredService<IDataProtectionProvider>().CreateProtector("bff.cookie.v1");
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
                () => { protectorWrong.Unprotect(ciphertext); });
        }

        // Production fails closed when encryption or persistent storage is missing.
        Assert.Throws<InvalidOperationException>(() =>
            BuildProvider(repo, "davids-api-gateway", key: null, envName: "Production"));

        var noStoreProd = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Production" });
        noStoreProd.Configuration["DataProtection:MasterKey"] = masterKey;
        Assert.Throws<InvalidOperationException>(() =>
            noStoreProd.Services.AddDataProtection()
                .ConfigureDavidsDataProtection(noStoreProd.Configuration, noStoreProd.Environment, "davids-api-gateway"));

        // X.509 PEM certificate wrapping also encrypts keys at rest cleanly.
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var certReq = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=davids-dp-test",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var certStore = new List<System.Xml.Linq.XElement>();
        var certHost = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Production" });
        certHost.Configuration["DataProtection:CertificatePem"] = cert.ExportCertificatePem();
        certHost.Configuration["DataProtection:CertificateKeyPem"] = rsa.ExportPkcs8PrivateKeyPem();
        certHost.Services.AddDataProtection()
            .ConfigureDavidsDataProtection(
                certHost.Configuration,
                certHost.Environment,
                "davids-admin-identity",
                _ => new InMemoryXmlRepository(certStore));
        using var certSp = certHost.Services.BuildServiceProvider();
        var certProtector = certSp.GetRequiredService<IDataProtectionProvider>().CreateProtector("state");
        var protectedVal = certProtector.Protect("hello-x509");
        Assert.Equal("hello-x509", certProtector.Unprotect(protectedVal));
        var certXml = certStore.Single().ToString();
        Assert.Contains("encryptedSecret", certXml, StringComparison.Ordinal);
        Assert.Contains("EncryptedData", certXml, StringComparison.Ordinal);
        Assert.DoesNotContain("<masterKey", certXml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void SecurityAuditMetricsEmitExpectedInstrumentsAndTags()
    {
        var recorded = new List<(string Instrument, long Value, Dictionary<string, object> Tags)>();
        using var listener = new System.Diagnostics.Metrics.MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == DavidsSecurityMetrics.MeterName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            var dict = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (var kv in tags)
            {
                dict[kv.Key] = kv.Value!;
            }
            recorded.Add((instrument.Name, measurement, dict));
        });
        listener.Start();

        DavidsSecurityMetrics.RecordLoginAudit("admin", "account_locked", succeeded: false);
        DavidsSecurityMetrics.RecordRateLimitRejection("davids-api-gateway", "gateway");
        DavidsSecurityMetrics.RecordTokenRevocation("customer", "replay_cascade");
        DavidsSecurityMetrics.RecordBffCsrfRejection("davids-api-gateway", "/auth/logout");

        Assert.Contains(recorded, r =>
            r.Instrument == "davids.security.login_audit" &&
            r.Value == 1 &&
            Equals(r.Tags["domain"], "admin") &&
            Equals(r.Tags["outcome"], "account_locked") &&
            Equals(r.Tags["succeeded"], "false"));
        Assert.Contains(recorded, r =>
            r.Instrument == "davids.security.rate_limit_rejected" &&
            Equals(r.Tags["service"], "davids-api-gateway") &&
            Equals(r.Tags["policy"], "gateway"));
        Assert.Contains(recorded, r =>
            r.Instrument == "davids.security.token_revoked" &&
            Equals(r.Tags["domain"], "customer") &&
            Equals(r.Tags["source"], "replay_cascade"));
        Assert.Contains(recorded, r =>
            r.Instrument == "davids.security.bff_csrf_rejected" &&
            Equals(r.Tags["service"], "davids-api-gateway") &&
            Equals(r.Tags["endpoint"], "/auth/logout"));
    }

    private sealed class InMemoryXmlRepository(List<System.Xml.Linq.XElement> elements)
        : Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository
    {
        public IReadOnlyCollection<System.Xml.Linq.XElement> GetAllElements()
            => elements.Select(e => new System.Xml.Linq.XElement(e)).ToList().AsReadOnly();

        public void StoreElement(System.Xml.Linq.XElement element, string? friendlyName)
            => elements.Add(new System.Xml.Linq.XElement(element));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void ServiceDefaultsAssemblyMaintainsCleanSharedKernelDependencies()
    {
        var assembly = typeof(DavidsSecurityMetrics).Assembly;
        var referencedNames = assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Davids.Services.", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Davids.APIGateway", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Davids.Frontend", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Aspire.Hosting", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
    }
}
