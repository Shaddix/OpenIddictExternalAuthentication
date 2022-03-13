# OpenIddictExternalAuthentication
OpenIddict extension that allows adding *Login with Facebook* or *Login with Google* buttons into your React/Angular/PlainJS/whatever SPA (implying you are using OpenIddict on backend).
Based on [OpenIddict Samples](https://github.com/openiddict/openiddict-samples), and could be treated as another sample with JS client and external authentication providers.
Implementation is based on Kevin Chalet answers on [external provider issue]().

Here's the [demo](https://openiddict.arturdr.ru) if you care. The shown page uses vanilla JS, and has several buttons to log in via different providers.
![Example workflow](example.gif)

# How to

1. It's implied, that openiddict is installed and configured in your project already (if it's not, head over to one of the [samples](https://github.com/openiddict/openiddict-samples)).
2. Install nuget to add the library to your project.
   ```dotnet add package Shaddix.OpenIddict.ExternalAuthentication```

3. Create you own `AuthorizationController` by inheriting from `OpenIdAuthorizationControllerBase`. This could look like:
   ```csharp
   public class AuthorizationController : OpenIdAuthorizationControllerBase<IdentityUser, string>
   {
       public AuthorizationController(SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOpenIddictClientConfigurationProvider clientConfigurationProvider) : base(signInManager, userManager,
        clientConfigurationProvider)
        {
        }

   }
   ```
4. Override some functions (e.g. `CreateNewUser` or `GetClaims`) if you want to customize user creation behavior or provide more claims.
5. From `Configure` function in `Startup.cs` add the following calls (in addition to standard OpenIddict setup):
   ```c#
   services
      .AddOpenIddict()
      .AddOpenIddictConfigurations(Configuration)
      .AddDefaultAuthorizationController()
   ```
6. Add external auth providers (i.e. `.AddAuthentication().AddGoogle()`, `.AddFacebook()`, etc.). Follow instructions on how to set up applications on [OAuth provider side](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-5.0).

You could also take a look at [OpenIddictExternalAuthentication.Example](OpenIddictExternalAuthentication.Example) for example usage (keep in mind, that there are hardcoded ClientId/ClientSecret for FB and Google within Example app. They are for demo purposes and everyone can use them, so beware).

## Frontend
1. Use some proven openid client library (I personally recommend [oidc-client-ts](https://github.com/authts/oidc-client-ts)).
2. Use standard auth code flow according to the library instructions, pointing to standard Authorize endpoint and passing `?provider=Google` as a query parameter (i.e. authorization endpoint should look like `/connect/authorize?provider=Google`).
3. You could check example implementation in [plain-js](OpenIddictExternalAuthentication.Example/wwwroot/index.html) or [React]()

## External user storage
We use standard Asp.Net Identity mechanism to store external logins (namely, `AspNetUserLogins` table). To find a user by external OAuth id you need to use `_userManager.FindByLoginAsync(providerName, externalUserId)`
