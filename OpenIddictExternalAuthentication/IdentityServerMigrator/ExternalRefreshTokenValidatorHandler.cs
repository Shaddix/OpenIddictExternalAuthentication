using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;

public class ExternalRefreshTokenValidatorHandler<TUser>
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenContext> where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly List<IExternalRefreshTokenValidator> _externalRefreshTokenValidators;

    public ExternalRefreshTokenValidatorHandler(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        IEnumerable<IExternalRefreshTokenValidator> externalRefreshTokenValidators
    )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _externalRefreshTokenValidators = externalRefreshTokenValidators.ToList();
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenContext context)
    {
        if (context.Principal != null)
            return;

        var request = context.Request;
        if (!request.IsRefreshTokenGrantType())
            return;

        var refreshToken = request.RefreshToken;
        if (string.IsNullOrEmpty(refreshToken))
            return;

        foreach (var externalRefreshTokenValidator in _externalRefreshTokenValidators)
        {
            var info = await externalRefreshTokenValidator.GetRefreshTokenInfo(
                refreshToken,
                request.ClientId
            );
            if (info == null)
                continue;

            var user = await _userManager.FindByIdAsync(info.UserId);
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            context.Principal = principal
                .SetTokenType(OpenIddictConstants.TokenTypeHints.RefreshToken)
                .SetScopes(info.Scopes);
        }
    }
}
