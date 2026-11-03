using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace Davids.ServiceDefaults;

public static class DavidsRoles
{
    public const string Customer = "user";
    public const string Admin = "admin";
    public const string Support = "support";
    public const string Auditor = "auditor";

    public static readonly IReadOnlyList<string> AllWorkforceRoles = [Admin, Support, Auditor];
    public static readonly IReadOnlyList<string> CustomerSupportWorkforceRoles = [Admin, Support];
    public static readonly IReadOnlyList<string> IamReadWorkforceRoles = [Admin, Auditor];

    public static bool TryNormalizeWorkforceRole(string? role, out string normalizedRole)
    {
        if (!string.IsNullOrWhiteSpace(role))
        {
            var candidate = role.Trim().ToLowerInvariant();
            if (candidate is Admin or Support or Auditor)
            {
                normalizedRole = candidate;
                return true;
            }
        }

        normalizedRole = string.Empty;
        return false;
    }

    public static bool IsWorkforceRole(string? role) =>
        TryNormalizeWorkforceRole(role, out _);

    public static bool CanMutateCustomers(string? role) =>
        string.Equals(role, Admin, StringComparison.Ordinal) ||
        string.Equals(role, Support, StringComparison.Ordinal);

    public static bool CanReadWorkforce(string? role) =>
        string.Equals(role, Admin, StringComparison.Ordinal) ||
        string.Equals(role, Support, StringComparison.Ordinal) ||
        string.Equals(role, Auditor, StringComparison.Ordinal);

    public static bool CanManageEmployees(string? role) =>
        string.Equals(role, Admin, StringComparison.Ordinal);
}

public static class DavidsAuthorities
{
    public const string Customer = "customer";
    public const string Employee = "employee";
}

public static class DavidsAuthHeaders
{
    public const string UserId = "X-Auth-UserId";
    public const string Email = "X-Auth-Email";
    public const string Role = "X-Auth-Role";
    public const string Authority = "X-Auth-Authority";
    public const string CorrelationId = "X-Correlation-Id";

    public static readonly IReadOnlyList<string> AllSpoofableAuthHeaders =
    [
        UserId,
        Email,
        Role,
        Authority
    ];
}

public sealed record DavidsActorContext(
    string ActorSub,
    string? ActorEmail,
    string ActorRole,
    string ActorAuthority,
    string? CorrelationId)
{
    public bool IsEmployee => string.Equals(ActorAuthority, DavidsAuthorities.Employee, StringComparison.Ordinal);
    public bool IsCustomer => string.Equals(ActorAuthority, DavidsAuthorities.Customer, StringComparison.Ordinal);

    public static DavidsActorContext FromPrincipal(ClaimsPrincipal principal, HttpContext? httpContext = null)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var sub = principal.FindFirstValue("sub")
                  ?? principal.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? string.Empty;
        if (Guid.TryParse(sub, out var parsedSub))
        {
            sub = parsedSub.ToString("D");
        }

        var email = principal.FindFirstValue("email")
                    ?? principal.FindFirstValue(ClaimTypes.Email);
        var role = principal.FindFirstValue("role")
                   ?? principal.FindFirstValue(ClaimTypes.Role)
                   ?? string.Empty;

        var authority = DavidsRoles.IsWorkforceRole(role)
            ? DavidsAuthorities.Employee
            : string.Equals(role, DavidsRoles.Customer, StringComparison.Ordinal)
                ? DavidsAuthorities.Customer
                : "unknown";

        var correlationId = ResolveCorrelationId(httpContext);
        return new DavidsActorContext(sub, email, role, authority, correlationId);
    }

    public static string? ResolveCorrelationId(HttpContext? httpContext)
    {
        if (httpContext is null)
        {
            return null;
        }

        var raw = httpContext.Request.Headers[DavidsAuthHeaders.CorrelationId].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(raw) && raw.Length <= 128)
        {
            return raw.Trim();
        }

        return string.IsNullOrWhiteSpace(httpContext.TraceIdentifier)
            ? null
            : httpContext.TraceIdentifier;
    }
}

public sealed record ChangeAuditFieldChange(
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("oldValue")] string? OldValue,
    [property: JsonPropertyName("newValue")] string? NewValue);

public sealed record ChangeAuditEntryDto(
    Guid Id,
    string Service,
    string Action,
    string TargetType,
    string TargetId,
    string? TargetLabel,
    string ActorSub,
    string? ActorEmail,
    string ActorRole,
    string ActorAuthority,
    IReadOnlyList<ChangeAuditFieldChange> Changes,
    string? CorrelationId,
    DateTime OccurredAtUtc);

public sealed class ChangeAuditDiffBuilder
{
    public const string RedactedPlaceholder = "[REDACTED]";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false
    };

    private static readonly string[] ProhibitedSensitiveKeywords =
    [
        "password",
        "secret",
        "token",
        "credential",
        "privatekey",
        "signingkey",
        "masterkey"
    ];

    private readonly List<ChangeAuditFieldChange> _changes = [];

    public bool HasChanges => _changes.Count > 0;

    public IReadOnlyList<ChangeAuditFieldChange> Changes => _changes;

    public ChangeAuditDiffBuilder Compare(string field, string? oldValue, string? newValue)
    {
        ValidateNonSensitiveFieldName(field);
        var normalizedOld = NormalizeValue(oldValue);
        var normalizedNew = NormalizeValue(newValue);
        if (!string.Equals(normalizedOld, normalizedNew, StringComparison.Ordinal))
        {
            _changes.Add(new ChangeAuditFieldChange(field.Trim(), normalizedOld, normalizedNew));
        }

        return this;
    }

    public ChangeAuditDiffBuilder RecordCreated(string field, string? newValue)
    {
        ValidateNonSensitiveFieldName(field);
        _changes.Add(new ChangeAuditFieldChange(field.Trim(), null, NormalizeValue(newValue)));
        return this;
    }

    public ChangeAuditDiffBuilder RecordRedacted(string field)
    {
        if (string.IsNullOrWhiteSpace(field))
        {
            throw new ArgumentException("Audit field name cannot be empty.", nameof(field));
        }

        _changes.Add(new ChangeAuditFieldChange(field.Trim(), RedactedPlaceholder, RedactedPlaceholder));
        return this;
    }

    public string BuildJson() => JsonSerializer.Serialize(_changes, SerializerOptions);

    public static IReadOnlyList<ChangeAuditFieldChange> ParseChanges(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        return JsonSerializer.Deserialize<List<ChangeAuditFieldChange>>(json, SerializerOptions)
               ?? [];
    }

    private static void ValidateNonSensitiveFieldName(string field)
    {
        if (string.IsNullOrWhiteSpace(field))
        {
            throw new ArgumentException("Audit field name cannot be empty.", nameof(field));
        }

        var normalized = field.Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();

        foreach (var keyword in ProhibitedSensitiveKeywords)
        {
            if (normalized.Contains(keyword, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Sensitive field '{field}' cannot be passed to ChangeAuditDiffBuilder.Compare/RecordCreated; use RecordRedacted instead.");
            }
        }
    }

    private static string? NormalizeValue(string? value) =>
        value is null ? null : (value.Length > 512 ? value[..512] : value);
}
