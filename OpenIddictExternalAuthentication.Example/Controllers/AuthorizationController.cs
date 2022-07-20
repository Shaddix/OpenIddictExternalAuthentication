using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Shaddix.OpenIddict.ExternalAuthentication.Example.Permissions;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

namespace Shaddix.OpenIddict.ExternalAuthentication.Example.Controllers;

public class AuthorizationController : OpenIdAuthorizationControllerBase<IdentityUser, string>
{
    public AuthorizationController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOpenIddictClientConfigurationProvider clientConfigurationProvider,
        ILogger<AuthorizationController> logger
    ) : base(signInManager, userManager, clientConfigurationProvider, logger) { }

    protected override async Task<IList<Claim>> GetClaims(
        IdentityUser user,
        OpenIddictRequest openIddictRequest
    )
    {
        var claims = await base.GetClaims(user, openIddictRequest);
        claims.Add(new Claim(ClaimType.Permission, Permission.UserManagement.ToString()));
        return claims;
    }
}
