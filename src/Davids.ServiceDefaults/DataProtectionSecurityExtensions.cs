using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Davids.ServiceDefaults;

public sealed class DataProtectionKeyRingSettings
{
    public string? MasterKey { get; set; }
    public string? CertificatePem { get; set; }
    public string? CertificateKeyPem { get; set; }
    public string? KeyDirectory { get; set; }
    public int KeyLifetimeDays { get; set; } = 90;
}

public sealed class AesGcmDataProtectionKeyMaterial
{
    private static readonly byte[] HkdfSalt = Encoding.UTF8.GetBytes("Davids.DataProtection.KeyWrap.Salt.v1");

    public string ApplicationName { get; }
    internal byte[] DerivedWrappingKey { get; }
    internal byte[] AssociatedData { get; }

    public AesGcmDataProtectionKeyMaterial(string applicationName, string? masterKey)
    {
        if (string.IsNullOrWhiteSpace(applicationName))
        {
            throw new ArgumentException("Data Protection application name is required.", nameof(applicationName));
        }

        var trimmed = masterKey?.Trim() ?? string.Empty;
        if (trimmed.Length < 32)
        {
            throw new InvalidOperationException(
                $"DataProtection:MasterKey for '{applicationName}' must be at least 32 characters (256 bits of key material).");
        }

        ApplicationName = applicationName;
        AssociatedData = Encoding.UTF8.GetBytes($"davids-dp-v1:{applicationName}");
        var ikm = Encoding.UTF8.GetBytes(trimmed);
        DerivedWrappingKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm,
            outputLength: 32,
            salt: HkdfSalt,
            info: AssociatedData);
    }
}

/// <summary>
/// Encrypts ASP.NET Core Data Protection key-ring XML elements at rest using 256-bit AES-GCM
/// with a key derived via HKDF-SHA256 and AEAD AAD bound to the isolated service application name.
/// </summary>
public sealed class AesGcmDataProtectionXmlEncryptor(AesGcmDataProtectionKeyMaterial material) : IXmlEncryptor
{
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSizeBytes];

        using (var aesGcm = new AesGcm(material.DerivedWrappingKey, TagSizeBytes))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag, material.AssociatedData);
        }

        CryptographicOperations.ZeroMemory(plaintextBytes);

        // Wire envelope: [version=1 (1B)][nonce (12B)][tag (16B)][ciphertext (NB)]
        var envelope = new byte[1 + NonceSizeBytes + TagSizeBytes + ciphertext.Length];
        envelope[0] = 1;
        Buffer.BlockCopy(nonce, 0, envelope, 1, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, envelope, 1 + NonceSizeBytes, TagSizeBytes);
        Buffer.BlockCopy(ciphertext, 0, envelope, 1 + NonceSizeBytes + TagSizeBytes, ciphertext.Length);

        var encryptedElement = new XElement(
            "encryptedKey",
            new XComment(" Encrypted at rest with AES-256-GCM (HKDF-SHA256, service-bound AAD). "),
            new XElement("value", Convert.ToBase64String(envelope)));

        return new EncryptedXmlInfo(encryptedElement, typeof(AesGcmDataProtectionXmlDecryptor));
    }
}

/// <summary>
/// Decrypts AES-256-GCM wrapped ASP.NET Core Data Protection key-ring XML elements.
/// Activated by ASP.NET Core Data Protection via <see cref="IServiceProvider"/>.
/// </summary>
public sealed class AesGcmDataProtectionXmlDecryptor(IServiceProvider services) : IXmlDecryptor
{
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);

        var material = services.GetRequiredService<AesGcmDataProtectionKeyMaterial>();
        var rawValue = encryptedElement.Element("value")?.Value
            ?? throw new CryptographicException("Encrypted Data Protection key element is missing <value>.");

        var envelope = Convert.FromBase64String(rawValue);
        if (envelope.Length <= 1 + NonceSizeBytes + TagSizeBytes || envelope[0] != 1)
        {
            throw new CryptographicException("Unsupported or truncated Data Protection encrypted key envelope.");
        }

        var nonce = envelope.AsSpan(1, NonceSizeBytes);
        var tag = envelope.AsSpan(1 + NonceSizeBytes, TagSizeBytes);
        var ciphertext = envelope.AsSpan(1 + NonceSizeBytes + TagSizeBytes);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aesGcm = new AesGcm(material.DerivedWrappingKey, TagSizeBytes);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, material.AssociatedData);
            var xml = Encoding.UTF8.GetString(plaintext);
            return XElement.Parse(xml);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

public static class DataProtectionSecurityExtensions
{
    public static IDataProtectionBuilder ConfigureDavidsDataProtection(
        this IDataProtectionBuilder builder,
        IConfiguration configuration,
        IHostEnvironment environment,
        string applicationName,
        Func<IServiceProvider, IXmlRepository?>? externalRepositoryFactory = null,
        bool externalStoreConfigured = true)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        if (string.IsNullOrWhiteSpace(applicationName))
        {
            throw new ArgumentException("A non-empty Data Protection application name is required.", nameof(applicationName));
        }

        var settings = configuration.GetSection("DataProtection").Get<DataProtectionKeyRingSettings>()
            ?? new DataProtectionKeyRingSettings();

        builder.SetApplicationName(applicationName)
            .SetDefaultKeyLifetime(TimeSpan.FromDays(Math.Max(7, settings.KeyLifetimeDays)));

        var hasKeyDirectory = !string.IsNullOrWhiteSpace(settings.KeyDirectory);
        if (hasKeyDirectory)
        {
            var dir = Directory.CreateDirectory(settings.KeyDirectory!.Trim());
            builder.PersistKeysToFileSystem(dir);
        }

        if (externalRepositoryFactory is not null)
        {
            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp =>
                new ConfigureOptions<KeyManagementOptions>(options =>
                {
                    var repository = externalRepositoryFactory(sp);
                    if (repository is not null)
                    {
                        options.XmlRepository = repository;
                    }
                }));
        }

        var hasPersistentStore = (externalRepositoryFactory is not null && externalStoreConfigured) || hasKeyDirectory;
        if (environment.IsProduction() && !hasPersistentStore)
        {
            throw new InvalidOperationException(
                $"Production deployment of '{applicationName}' requires a persistent Data Protection key ring store " +
                "(SQL/Redis repository or DataProtection:KeyDirectory).");
        }

        var hasCert = !string.IsNullOrWhiteSpace(settings.CertificatePem);
        var hasMasterKey = !string.IsNullOrWhiteSpace(settings.MasterKey);

        if (hasCert)
        {
            if (string.IsNullOrWhiteSpace(settings.CertificateKeyPem))
            {
                throw new InvalidOperationException(
                    $"DataProtection:CertificateKeyPem is required when DataProtection:CertificatePem is set for '{applicationName}'.");
            }

            // Copy via PFX round-trip on Windows/Linux so ephemeral private keys remain usable for XML encryption/decryption.
            using var ephemeral = X509Certificate2.CreateFromPem(settings.CertificatePem!, settings.CertificateKeyPem!);
            var cert = X509CertificateLoader.LoadPkcs12(
                ephemeral.Export(X509ContentType.Pfx),
                password: null,
                X509KeyStorageFlags.Exportable);
            builder.ProtectKeysWithCertificate(cert);
        }
        else if (hasMasterKey)
        {
            var material = new AesGcmDataProtectionKeyMaterial(applicationName, settings.MasterKey);
            builder.Services.AddSingleton(material);
            builder.Services.Configure<KeyManagementOptions>(options =>
            {
                options.XmlEncryptor = new AesGcmDataProtectionXmlEncryptor(material);
            });
        }
        else if (environment.IsProduction())
        {
            throw new InvalidOperationException(
                $"Production deployment of '{applicationName}' requires at-rest Data Protection key encryption " +
                "(configure DataProtection:MasterKey in Vault or DataProtection:CertificatePem + CertificateKeyPem).");
        }

        return builder;
    }
}
