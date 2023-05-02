using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;

public class IdentityServerRefreshTokenValidator<TDbContext> : IExternalRefreshTokenValidator
    where TDbContext : DbContext
{
    private readonly TDbContext _dbContext;

    public IdentityServerRefreshTokenValidator(TDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenInfo> GetRefreshTokenInfo(string refreshToken, string? clientId)
    {
        var key = GetHashedKey(refreshToken);
        var nowDate = DateTime.UtcNow;
        var userId = await _dbContext.Database
            .SqlQuery<string>(
                $"SELECT \"SubjectId\" as \"Value\" FROM \"PersistedGrants\" WHERE \"Type\" = 'refresh_token' AND \"Key\" = {key} AND \"ClientId\" = {clientId} AND \"Expiration\" > {nowDate}"
            )
            .FirstOrDefaultAsync();

        if (string.IsNullOrEmpty(userId))
            return null;

        return new RefreshTokenInfo(userId, new[] { "offline_access" });
    }

    private const string KeySeparator = ":";
    private const string HexEncodingFormatSuffix = "-1";
    private const string GrantType = "refresh_token";

    /// <summary>
    /// Gets the hashed key.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns></returns>
    public static string GetHashedKey(string value)
    {
        var key = (value + KeySeparator + GrantType);

        if (value.EndsWith(HexEncodingFormatSuffix))
        {
            // newer format >= v6; uses hex encoding to avoid collation issues
            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(key);
                var hash = sha.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        // old format <= v5
        return Sha256(key);
    }

    /// <summary>
    /// Creates a SHA256 hash of the specified input.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>A hash</returns>
    private static string Sha256(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = sha.ComputeHash(bytes);

        return Convert.ToBase64String(hash);
    }
}
