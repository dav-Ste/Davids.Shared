using Elastic.Serilog.Sinks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace Davids.ServiceDefaults;

public static class LoggingExtensions
{
    public static void AddExternalLogging(this IHostApplicationBuilder builder, string serviceName = "davids-identity")
    {
        var config = builder.Configuration;
        var seq = config.GetValue<bool>("LoggingSinks:Seq:Enabled");
        var file = config.GetValue<bool>("LoggingSinks:File:Enabled");
        var elastic = config.GetValue<bool>("LoggingSinks:Elasticsearch:Enabled");
        if (!seq && !file && !elastic)
        {
            return;
        }

        var logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Service", serviceName);

        if (seq)
        {
            logger.WriteTo.Seq(
                config["LoggingSinks:Seq:Url"] ?? throw new InvalidOperationException("Seq URL required."),
                apiKey: config["LoggingSinks:Seq:ApiKey"]);
        }

        if (file)
        {
            logger.WriteTo.File(
                config["LoggingSinks:File:Path"] ?? $"logs/{serviceName.Replace("davids-", string.Empty, StringComparison.Ordinal)}-.log",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7);
        }

        if (elastic)
        {
            logger.WriteTo.Elasticsearch(
                new[] { new Uri(config["LoggingSinks:Elasticsearch:Url"] ?? throw new InvalidOperationException("Elasticsearch URL required.")) },
                options => { options.BootstrapMethod = Elastic.Ingest.Elasticsearch.BootstrapMethod.Failure; },
                transport =>
                {
                    var key = config["LoggingSinks:Elasticsearch:ApiKey"];
                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        transport.Authentication(new Elastic.Transport.ApiKey(key));
                    }
                });
        }

        // Retain built-in console and Aspire OTLP logging; this provider supplies only external sinks.
        builder.Logging.AddSerilog(logger.CreateLogger(), dispose: true);
    }
}
