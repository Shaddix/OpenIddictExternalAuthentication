using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;

public interface IExternalRefreshTokenValidator
{
    Task<string> GetUserIdByRefreshToken(string refreshToken, string? clientId);
}
