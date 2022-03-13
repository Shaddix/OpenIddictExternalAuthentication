using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

namespace Shaddix.OpenIddict.ExternalAuthentication.Example.Permissions;

public class AuthorizationController : OpenIdAuthorizationControllerBase<IdentityUser, string>
{
    public AuthorizationController(SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOpenIddictClientConfigurationProvider clientConfigurationProvider) : base(signInManager, userManager,
        clientConfigurationProvider)
    {
    }

    protected override async Task<IList<Claim>> GetClaims(IdentityUser user)
    {
        var claims = await base.GetClaims(user);
        claims.Add(new Claim(ClaimType.Permission, Permission.UserManagement.ToString()));
        return claims;
    }
}