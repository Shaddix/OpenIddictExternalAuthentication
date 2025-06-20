namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

public class CookiesConfiguration
{
    /// <summary>
    /// If true the cookies lifetime is attached to browser tab/window
    /// (when it's closed, the cookie is removed and re-authentication is required).
    /// False by default
    /// </summary>
    public bool IsUseSessionCookie { get; set; } = false;
    
    /// <summary>
    /// Disables the call to options.RegisterScopes with available client scopes (enabled by default)
    /// </summary>
    public CookiesConfiguration UseSessionCookie()
    {
        IsUseSessionCookie = true;
        return this;
    }
}