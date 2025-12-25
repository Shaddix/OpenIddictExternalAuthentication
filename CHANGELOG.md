# Changelog

## 2.10.6
Add support for returning AccessToken / RefreshToken together with HttpOnly cookie authentication.
To use that configure the clients with `"UseHttpOnlyCookiesKeepPayload": true` (e.g. in `appsettings.json`)


## 2.9.1
Add support for HttpOnly cookie authentication.
To enable it you should call `services.AddOpenIddict().AddSupportForHttpOnlyCookieClients()` and configure the clients with `"UseHttpOnlyCookies": true` (e.g. in `appsettings.json`)

## 2.8.1
Update OpenIdDict to v6

## 2.6.1 UseOpenIdDictConversionMiddleware
Added `app.UseOpenIdDictConversionMiddleware()` which helps to support old clients when migrating from IdentityServer. It allows to do the following:
1. Remove non-existing scopes
2. Remove header authorization (if client_id/client_secret are passed in Form parameters)
3. Remove client_secret for public clients (otherwise OpenIdDict complains)
4. Change name of form parameters (e.g. `userName` -> `username`)

## 2.5.1 EnableIdentityServerRefreshTokens

`EnableIdentityServerRefreshTokens()` option that eases the migration from IdentityServer (i.e., Refresh Tokens from IdentityServer will still work, if `PersistedGrants` table remains)
Upgraded to .NET 7.