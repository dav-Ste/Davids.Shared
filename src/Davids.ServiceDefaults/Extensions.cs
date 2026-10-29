using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Davids.ServiceDefaults;

public static class Extensions
{
    public static TBuilder AddServiceDefaults<TBuilder>(this TBuilder builder, string serviceName = "davids-identity")
        where TBuilder : IHostApplicationBuilder
    {
        builder.AddExternalLogging(serviceName);
        builder.Services.AddServiceDiscovery();
        builder.Services.ConfigureHttpClientDefaults(http => http.AddServiceDiscovery());
        builder.Services.AddHealthChecks();
        builder.Logging.AddOpenTelemetry(o =>
        {
            o.IncludeFormattedMessage = true;
            o.IncludeScopes = true;
        });

        var telemetry = builder.Services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(
                serviceName,
                serviceInstanceId: Environment.MachineName + "-" + Guid.NewGuid().ToString("N")))
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation()
                .AddMeter(DavidsSecurityMetrics.MeterName))
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation());

        if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
        {
            // Use signal-specific exporters everywhere. UseOtlpExporter cannot be mixed with these.
            void ConfigureAspire(OtlpExporterOptions o)
            {
                o.Endpoint = new Uri(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]!);
                o.Protocol = builder.Configuration["OTEL_EXPORTER_OTLP_PROTOCOL"] == "http/protobuf"
                    ? OtlpExportProtocol.HttpProtobuf
                    : OtlpExportProtocol.Grpc;
                o.Headers = builder.Configuration["OTEL_EXPORTER_OTLP_HEADERS"];
            }

            telemetry.WithTracing(t => t.AddOtlpExporter("aspire-traces", ConfigureAspire))
                .WithMetrics(m => m.AddOtlpExporter("aspire-metrics", ConfigureAspire));
            builder.Logging.AddOpenTelemetry(o => o.AddOtlpExporter("aspire-logs", ConfigureAspire));
        }

        if (builder.Configuration.GetValue<bool>("Telemetry:Jaeger:Enabled"))
        {
            telemetry.WithTracing(t => t.AddOtlpExporter("jaeger", o =>
            {
                o.Endpoint = new Uri(builder.Configuration["Telemetry:Jaeger:Endpoint"]
                    ?? throw new InvalidOperationException("Jaeger endpoint required."));
                o.Protocol = OtlpExportProtocol.HttpProtobuf;
            }));
        }

        if (builder.Configuration.GetValue<bool>("Telemetry:Prometheus:Enabled"))
        {
            telemetry.WithMetrics(m => m.AddOtlpExporter("prometheus", o =>
            {
                o.Endpoint = new Uri(builder.Configuration["Telemetry:Prometheus:Endpoint"]
                    ?? throw new InvalidOperationException("Prometheus endpoint required."));
                o.Protocol = OtlpExportProtocol.HttpProtobuf;
            }));
        }

        if (builder.Configuration.GetValue<bool>("Telemetry:InfluxDB:Enabled"))
        {
            telemetry.WithMetrics(m => m.AddOtlpExporter("influxdb", o =>
            {
                o.Endpoint = new Uri(builder.Configuration["Telemetry:InfluxDB:Endpoint"]
                    ?? throw new InvalidOperationException("InfluxDB collector endpoint required."));
                o.Protocol = OtlpExportProtocol.HttpProtobuf;
            }));
        }

        return builder;
    }

    public static IServiceCollection AddTrustedForwardedHeaders(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment,
        bool trustLoopbackInNonProduction = true)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var forwardLimit = Math.Max(1, configuration.GetValue("ForwardedHeaders:ForwardLimit", 1));
        var defaultTrustLoopback =
            trustLoopbackInNonProduction &&
            (environment.IsDevelopment() || environment.IsEnvironment("Testing"));
        var trustLoopback = configuration.GetValue("ForwardedHeaders:TrustLoopback", defaultTrustLoopback);

        var configuredProxies = ReadMultiValueSetting(configuration, "ForwardedHeaders:KnownProxies");
        var parsedProxies = new List<IPAddress>();
        foreach (var rawProxy in configuredProxies)
        {
            if (!IPAddress.TryParse(rawProxy, out var ip))
            {
                throw new InvalidOperationException($"Invalid IP address '{rawProxy}' in ForwardedHeaders:KnownProxies.");
            }

            parsedProxies.Add(ip);
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                parsedProxies.Add(ip.MapToIPv6());
            }
        }

        var configuredNetworks = ReadMultiValueSetting(configuration, "ForwardedHeaders:KnownNetworks");
        var parsedNetworks = new List<System.Net.IPNetwork>();
        foreach (var rawNetwork in configuredNetworks)
        {
            if (!System.Net.IPNetwork.TryParse(rawNetwork, out var network))
            {
                throw new InvalidOperationException($"Invalid CIDR network '{rawNetwork}' in ForwardedHeaders:KnownNetworks.");
            }

            parsedNetworks.Add(network);
        }

        var hasTrustedProxies = trustLoopback || parsedProxies.Count > 0 || parsedNetworks.Count > 0;

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();
            options.ForwardLimit = forwardLimit;

            // CRITICAL: In ASP.NET Core ForwardedHeadersMiddleware, an empty KnownProxies + empty KnownIPNetworks
            // disables the known-proxy check and trusts ALL callers! When no trusted proxies are configured,
            // disable header forwarding completely so untrusted peers can never spoof X-Forwarded-For.
            if (!hasTrustedProxies)
            {
                options.ForwardedHeaders = ForwardedHeaders.None;
                return;
            }

            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            if (trustLoopback)
            {
                options.KnownProxies.Add(IPAddress.Loopback);
                options.KnownProxies.Add(IPAddress.IPv6Loopback);
                options.KnownProxies.Add(IPAddress.Loopback.MapToIPv6());
            }

            foreach (var proxy in parsedProxies)
            {
                options.KnownProxies.Add(proxy);
            }

            foreach (var network in parsedNetworks)
            {
                options.KnownIPNetworks.Add(network);
            }
        });

        return services;
    }

    public static WebApplication UseTrustedForwardedHeaders(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.UseForwardedHeaders();
        return app;
    }

    private static IReadOnlyList<string> ReadMultiValueSetting(IConfiguration configuration, string sectionPath)
    {
        var results = new List<string>();
        var section = configuration.GetSection(sectionPath);
        if (!string.IsNullOrWhiteSpace(section.Value))
        {
            foreach (var part in section.Value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                results.Add(part);
            }
        }

        foreach (var child in section.GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(child.Value))
            {
                foreach (var part in child.Value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    results.Add(part);
                }
            }
        }

        return results;
    }

    public static WebApplication MapDefaultEndpoints(this WebApplication app)
    {
        app.MapHealthChecks("/health").AllowAnonymous();
        app.MapHealthChecks("/alive", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
        return app;
    }
}
