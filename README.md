# OpenIddictExternalAuthentication
OpenIddict extension that allows adding *Login with Facebook* or *Login with Google* buttons into your React/Angular/whatever SPA (implying you are using OpenIddict on backend).

Here's the [demo](https://openiddict.arturdr.ru) if you care. The shown page uses vanilla JS, and has several buttons to log in via different providers.
![Example workflow](example.gif)

# Goal
The project goal is to allow integration of external OAuth providers (e.g. Google, Facebook, etc.) into your SinglePageApplications applications (React, Angular, plain-old-js, whatever), with minimum amount of needed code, and without the need to show Identity UI to the user.

This is a backend library, that integrates with Asp.Net Core 5.0+.

The library is kept minimal, as we reuse all [official](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/?view=aspnetcore-2.2) and [non-official](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/other-logins?view=aspnetcore-2.2) authentication providers (i.e. library doesn't need to be updated when those external providers change).

Library is significantly reworked in v1.0, so there's no provider-specific code at all.

# How to

## Backend
1. Install nuget to add the library to your project.

   ```dotnet add package OpenIddictExternalAuthentication```

1. From `ConfigureServices` call `services.ConfigureExternalAuth()`.

1. From `Configure` call `app.UseExternalAuth()` BEFORE `UseAuthentication()`.

1. If you are using IdentityServer, add the grant validator:
    ```services.AddIdentityServer().AddExtensionGrantValidator<ExternalAuthenticationGrantValidator<IdentityUser, string>>()```.
   
    Also include 'external' grant type to existing grant types of your Client (SPA)

1. That's it. Just `.AddAuthentication().AddGoogle()` or `.AddFacebook()` as usual. Follow instructions on how to set up applications on [OAuth provider side](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-5.0).

You could also take a look at [IdentityOAuthSpaExtensions.Example](IdentityOAuthSpaExtensions.Example) for example usage (keep in mind, that there are hardcoded ClientId/ClientSecret for FB and Google within Example app. They are for demo purposes and everyone can use them, so beware).

## Frontend
1. Copy the following [typescript](https://raw.githubusercontent.com/Shaddix/IdentityOAuthSpaExtensions/master/IdentityOAuthSpaExtensions.Example/wwwroot/js/auth-social.ts) (or [compiled JS](https://raw.githubusercontent.com/Shaddix/IdentityOAuthSpaExtensions/master/IdentityOAuthSpaExtensions.Example/wwwroot/js/auth-social.js)) file into your sourcecode (adjust the `backendUri` variable on top if your SPA is on different host than backend).
1. Place some SocialLogin buttons in your SPA and execute `getOAuthCode('Google')` from onClick handler.
1. Request access token from your Identity Server, passing received oAuthCode to it. In total you should have something like this:
    ```
    // call this function from SocialLogin buttons onClick  
    async function signInVia(provider) {
        const data = await getOAuthCode(provider);
        await getAccessToken(data.provider, data.code);
    }

    async function getAccessToken(provider, code) {
        const response = await fetch('/connect/token',
                {
                    method: 'POST',
                    // you will need to adjust SCOPE here
                    body: grant_type=external&scope=local&provider=${provider}&code=${code}`,
                    headers: {
                        // you definitely need to use clien/secret of YOUR APP here
                        'Authorization': 'Basic Y2xpZW50OnNlY3JldA==', //base64 encoded 'client:secret'
                        'Content-Type': 'application/x-www-form-urlencoded',
                    }
                });
        const jsonData = await response.json();
        _accessToken = jsonData.access_token;
        alert('access_token: '+ _accessToken);
        // make some requests to your API using this token!
    }    
   ```

# Identity Server integration
## Adding external grant (validate Auth Code and issue own JWT)
Typical scenario is that you use oAuth for authentication only, and then create the user in your local DB (via e.g. IdentityServer) and issue your own JWT with custom claims for later authorization.
This library perfectly supports this scenario in combination with [IdentityServer](https://docs.identityserver.io) using extension grants (https://docs.identityserver.io/en/latest/topics/grant_types.html#extension-grants).
To integrate with IdentityServer all you need to do is call
```services.AddIdentityServer().AddExtensionGrantValidator<ExternalAuthenticationGrantValidator<IdentityUser, string>>()```.
That will register an extension grant named `external` and you could authenticate from JS as [described above](#to-authenticate-get-access_token-using-identityserver)

### Customization
You could inherit from `ExternalAuthenticationGrantValidator<IdentityUser, string>` and provide your custom logic for any of the following methods:
- `CreateNewUser` - fill-in the fields of new User based on your business requirements and/or information received from oAuth provider
- `CreateResultForLocallyNotFoundUser` - here you could write your own business logic, regarding what to do when the user is logging in for the first time. You could write custom logic for user creation, or deny some users (based on email/id) from logging in.
- `GetUserName` - most useful if you don't override `CreateNewUser`. You could provide Username for newly created users based on oAuth provider info

## External user storage
We use standard Asp.Net Identity mechanism to store external logins (namely, `AspNetUserLogins` table). To find a user by external OAuth id you need to use `_userManager.FindByLoginAsync(providerName, externalUserId)`
