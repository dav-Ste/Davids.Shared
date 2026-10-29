using System.Diagnostics.Metrics;

namespace Davids.ServiceDefaults;

public static class DavidsSecurityMetrics
{
    public const string MeterName = "Davids.Security.Audit";

    private static readonly Meter AuditMeter = new(MeterName, "1.0.0");

    private static readonly Counter<long> LoginAuditCounter =
        AuditMeter.CreateCounter<long>(
            "davids.security.login_audit",
            unit: "{event}",
            description: "Total customer and administrator authentication/token audit outcomes.");

    private static readonly Counter<long> RateLimitRejectedCounter =
        AuditMeter.CreateCounter<long>(
            "davids.security.rate_limit_rejected",
            unit: "{request}",
            description: "Total HTTP 429 rate-limiter rejections across edge and OIDC endpoints.");

    private static readonly Counter<long> TokenRevokedCounter =
        AuditMeter.CreateCounter<long>(
            "davids.security.token_revoked",
            unit: "{token}",
            description: "Total RS256 access tokens added to the revocation denylist via RFC 7009 or replay cascade.");

    private static readonly Counter<long> BffCsrfRejectedCounter =
        AuditMeter.CreateCounter<long>(
            "davids.security.bff_csrf_rejected",
            unit: "{request}",
            description: "Total cookie-authenticated Administrator BFF requests rejected by CSRF defenses.");

    public static void RecordLoginAudit(string? domain, string? outcome, bool succeeded)
    {
        LoginAuditCounter.Add(
            1,
            new KeyValuePair<string, object?>("domain", domain ?? "unknown"),
            new KeyValuePair<string, object?>("outcome", outcome ?? "unknown"),
            new KeyValuePair<string, object?>("succeeded", succeeded ? "true" : "false"));
    }

    public static void RecordRateLimitRejection(string? service, string? policy)
    {
        RateLimitRejectedCounter.Add(
            1,
            new KeyValuePair<string, object?>("service", service ?? "unknown"),
            new KeyValuePair<string, object?>("policy", policy ?? "default"));
    }

    public static void RecordTokenRevocation(string? domain, string? source)
    {
        TokenRevokedCounter.Add(
            1,
            new KeyValuePair<string, object?>("domain", domain ?? "unknown"),
            new KeyValuePair<string, object?>("source", source ?? "unknown"));
    }

    public static void RecordBffCsrfRejection(string? service, string? endpoint)
    {
        BffCsrfRejectedCounter.Add(
            1,
            new KeyValuePair<string, object?>("service", service ?? "unknown"),
            new KeyValuePair<string, object?>("endpoint", endpoint ?? "unknown"));
    }
}
