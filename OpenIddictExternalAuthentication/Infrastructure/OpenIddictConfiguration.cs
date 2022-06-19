using System.Collections.Generic;
using OpenIddict.Abstractions;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// OpenIddict configuration
/// </summary>
public class OpenIddictConfiguration
{
    /// <summary>
    /// OpenId clients to be registered in openiddict
    /// </summary>
    public Dictionary<string, OpenIddictClientConfiguration> Clients { get; set; }
}

/// <summary>
/// Configuration of a single Client
/// </summary>
public class OpenIddictClientConfiguration : OpenIddictApplicationDescriptor
{
    /// <summary>
    /// Lifetime of an access token in seconds (3600 by default)
    /// </summary>
    public int? AccessTokenLifetime { get; set; }

    /// <summary>
    /// Rolling lifetime of a refresh token in seconds (14 days by default)
    /// </summary>
    public int? RefreshTokenLifetime { get; set; }
}
