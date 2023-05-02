namespace Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;

public record RefreshTokenInfo(string UserId, string[] Scopes);