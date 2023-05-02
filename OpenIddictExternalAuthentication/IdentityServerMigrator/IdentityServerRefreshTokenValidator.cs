using System;
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

    public async Task<string> GetUserIdByRefreshToken(string refreshToken, string? clientId)
    {
        var nowDate = DateTime.UtcNow;
        return await _dbContext.Database
            .SqlQuery<string>(
                $"SELECT \"SubjectId\" as Value FROM \"PersistedGrants\" WHERE \"Type\" = 'refresh_token' AND \"Key\" = {refreshToken} AND \"ClientId\" = {clientId} AND \"Expiration\" > {nowDate}"
            )
            .FirstOrDefaultAsync();
    }
}
