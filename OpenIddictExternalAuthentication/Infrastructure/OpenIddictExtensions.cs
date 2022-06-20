using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Convenience extensions for OpenIddict
/// </summary>
public static class OpenIddictExtensions
{
    /// <summary>
    /// Configures openiddict with signing certificate from appsettings.json
    /// </summary>
    public static OpenIddictServerBuilder AddSigningCertificateFromConfiguration(
        this OpenIddictServerBuilder options,
        IConfiguration configuration
    )
    {
        var signingCertificate = configuration.Get<OpenIdCertificateInfo>();
        return options.AddSigningCertificate(signingCertificate);
    }

    /// <summary>
    /// Configures openiddict with signing certificate
    /// </summary>
    public static OpenIddictServerBuilder AddSigningCertificate(
        this OpenIddictServerBuilder options,
        OpenIdCertificateInfo signingCertificate
    )
    {
        if (
            !string.IsNullOrEmpty(signingCertificate?.Password)
            && !string.IsNullOrEmpty(signingCertificate?.Base64Certificate)
        )
        {
            options.AddSigningCertificate(
                new MemoryStream(Convert.FromBase64String(signingCertificate.Base64Certificate)),
                signingCertificate.Password
            );
        }
        else
        {
            options.AddDevelopmentSigningCertificate();
        }

        return options;
    }

    /// <summary>
    /// Configures openiddict with encryption certificate from appsettings.json
    /// </summary>
    public static OpenIddictServerBuilder AddEncryptionCertificateFromConfiguration(
        this OpenIddictServerBuilder options,
        IConfiguration configuration
    )
    {
        OpenIdCertificateInfo encryptionCertificate = configuration.Get<OpenIdCertificateInfo>();
        return options.AddEncryptionCertificate(encryptionCertificate);
    }

    /// <summary>
    /// Configures openiddict with encryption certificate
    /// </summary>
    public static OpenIddictServerBuilder AddEncryptionCertificate(
        this OpenIddictServerBuilder options,
        OpenIdCertificateInfo encryptionCertificate
    )
    {
        if (
            !string.IsNullOrEmpty(encryptionCertificate?.Password)
            && !string.IsNullOrEmpty(encryptionCertificate?.Base64Certificate)
        )
        {
            options.AddEncryptionCertificate(
                new MemoryStream(Convert.FromBase64String(encryptionCertificate.Base64Certificate)),
                encryptionCertificate.Password
            );
        }
        else
        {
            options.AddDevelopmentEncryptionCertificate();
        }

        return options;
    }

    /// <summary>
    /// Registers implementation of IOption&lt;OpenIddictConfiguration&gt; and IOpenIddictClientConfigurationProvider
    /// </summary>
    public static OpenIddictBuilder AddOpenIddictConfiguration(
        this OpenIddictBuilder openIddictBuilder,
        IConfiguration configuration
    )
    {
        IServiceCollection services = openIddictBuilder.Services;
        services.AddTransient<
            IOpenIddictClientConfigurationProvider,
            OpenIddictClientConfigurationProvider
        >();
        services.Configure<OpenIddictConfiguration>(configuration);

        return openIddictBuilder;
    }

    /// <summary>
    /// Configures OpenIddict to use Token and Authorization endpoints
    /// </summary>
    public static OpenIddictBuilder AddDefaultAuthorizationController(
        this OpenIddictBuilder openIddictBuilder,
        Action<OpenIddictSettings>? configuration = null
    )
    {
        return openIddictBuilder.AddServer(options =>
        {
            var settings = new OpenIddictSettings(options);
            configuration?.Invoke(settings);

            if (settings.Configuration != null)
            {
                openIddictBuilder.AddOpenIddictConfiguration(settings.Configuration);
                var typedConfiguration = settings.Configuration.Get<OpenIddictConfiguration>();
                if (typedConfiguration?.EncryptionCertificate != null)
                {
                    options.AddEncryptionCertificate(typedConfiguration?.EncryptionCertificate);
                }
                if (typedConfiguration?.SigningCertificate != null)
                {
                    options.AddSigningCertificate(typedConfiguration?.SigningCertificate);
                }

                if (typedConfiguration?.Clients != null && typedConfiguration.Clients.Any())
                {
                    options.Services.AddTransient<ClientSeeder>();
                    options.Services.AddSingleton<IPublicUrlProvider>(
                        new PublicUrlProvider(
                            !string.IsNullOrEmpty(settings.PublicUrl)
                                ? settings.PublicUrl
                                : typedConfiguration.PublicUrl
                        )
                    );
                    options.Services.AddHostedService<SeedOpenIdClientConfigurationsWorker>();

                    if (!settings.IsScopeRegistrationDisabled)
                    {
                        string[] scopes = typedConfiguration.Clients
                            .SelectMany(x => x.Value?.Permissions ?? new HashSet<string>())
                            .Where(
                                x => x.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope)
                            )
                            .Select(
                                x =>
                                    x.Substring(
                                        OpenIddictConstants.Permissions.Prefixes.Scope.Length
                                    )
                            )
                            .ToArray();

                        options.RegisterScopes(scopes);
                    }
                }
            }

            options.SetTokenEndpointUris("/connect/token");
            options.UseAspNetCore().EnableTokenEndpointPassthrough();

            if (!settings.IsLogoutEndpointDisabled)
            {
                options.SetLogoutEndpointUris("/connect/logout");
                options.UseAspNetCore().EnableLogoutEndpointPassthrough();
            }

            if (!settings.IsAuthorizeFlowDisabled)
            {
                options
                    .AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange()
                    .SetAuthorizationEndpointUris("/connect/authorize");

                options.UseAspNetCore().EnableAuthorizationEndpointPassthrough();
            }

            if (settings.IsPasswordFlowAllowed)
            {
                options.AllowPasswordFlow();
            }

            if (settings.IsDeviceCodeFlowAllowed)
            {
                options
                    .AllowDeviceCodeFlow()
                    .SetDeviceEndpointUris("/connect/device")
                    .SetVerificationEndpointUris("/connect/verify");
                options.UseAspNetCore().EnableVerificationEndpointPassthrough();
            }

            if (!settings.IsRefreshTokenFlowDisabled)
            {
                options.AllowRefreshTokenFlow();
            }
        });
    }
}
