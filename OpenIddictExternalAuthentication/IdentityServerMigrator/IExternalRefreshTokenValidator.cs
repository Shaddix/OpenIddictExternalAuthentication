using System.Threading.Tasks;

namespace Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;

public interface IExternalRefreshTokenValidator
{
    Task<RefreshTokenInfo> GetRefreshTokenInfo(string refreshToken, string? clientId);
}
