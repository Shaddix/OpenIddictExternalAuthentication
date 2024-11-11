using System.Threading.Tasks;
using OpenIddict.Server;

namespace Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;

public interface IExternalRefreshTokenValidator
{
    Task<RefreshTokenInfo> GetRefreshTokenInfo(OpenIddictServerEvents.ValidateTokenContext context);
}
