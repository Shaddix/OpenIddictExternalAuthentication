using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
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
    public static void AddSigningCertificateFromConfiguration(
        this OpenIddictServerBuilder options,
        IConfiguration configuration,
        string configurationPath = "OpenId:SigningCertificate"
    )
    {
        var signingCertificate =
            configuration.GetSection(configurationPath).Get<OpenIdCertificateInfo>();
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
    }

    /// <summary>
    /// Configures openiddict with encryption certificate from appsettings.json 
    /// </summary>
    public static void AddEncryptionCertificateFromConfiguration(
        this OpenIddictServerBuilder options,
        IConfiguration configuration,
        string configurationPath = "OpenId:EncryptionCertificate"
    )
    {
        var encryptionCertificate =
            configuration.GetSection(configurationPath).Get<OpenIdCertificateInfo>();
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
    }

    /// <summary>
    /// Imports Application from appsettings.json into OpenId database
    /// </summary>
    public static async Task UseOpenIdDictApplicationsFromConfiguration(
        this IApplicationBuilder applicationBuilder
    )
    {
        using IServiceScope scope = applicationBuilder.ApplicationServices.CreateScope();
        IServiceProvider serviceProvider = scope.ServiceProvider;
        IOpenIddictApplicationManager manager =
            serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var configurationProvider =
            serviceProvider.GetRequiredService<IOpenIddictClientConfigurationProvider>();

        var clients = configurationProvider.GetAllConfigurations();

        foreach (OpenIddictClientConfiguration client in clients)
        {
            object clientObject =
                await manager.FindByClientIdAsync(client.ClientId!).ConfigureAwait(false);
            // See OpenIddictConstants.Permissions for available permissions

            if (clientObject is null)
            {
                await manager.CreateAsync(client).ConfigureAwait(false);
            }
            else
            {
                client.Type ??= "public";
                await manager.PopulateAsync(clientObject, client).ConfigureAwait(false);
                await manager.UpdateAsync(clientObject).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Registers implementation of IOption&lt;OpenIddictConfiguration&gt; and IOpenIddictClientConfigurationProvider
    /// </summary>
    public static OpenIddictBuilder AddOpenIddictConfigurations(
        this OpenIddictBuilder openIddictBuilder,
        IConfiguration configuration,
        string configurationSection = "OpenId"
    )
    {
        IServiceCollection services = openIddictBuilder.Services;
        services
            .AddTransient<IOpenIddictClientConfigurationProvider,
                OpenIddictClientConfigurationProvider>();
        services.Configure<OpenIddictConfiguration>(
            configuration.GetSection($"{configurationSection}")
        );

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
        return openIddictBuilder.AddServer(
            options =>
            {
                var settings = new OpenIddictSettings(options);
                configuration?.Invoke(settings);
                
                options.SetTokenEndpointUris("/connect/token");
                options
                    .UseAspNetCore()
                    .EnableTokenEndpointPassthrough();
                    
                
                if (!settings.IsLogoutEndpointDisabled)
                {
                    options.SetLogoutEndpointUris("/connect/logout");
                    options
                        .UseAspNetCore()
                        .EnableLogoutEndpointPassthrough();
                }

                if (!settings.IsAuthorizeFlowDisabled)
                {
                    options
                        .AllowAuthorizationCodeFlow()
                        .RequireProofKeyForCodeExchange()
                        .SetAuthorizationEndpointUris("/connect/authorize");

                    options
                        .UseAspNetCore()
                        .EnableAuthorizationEndpointPassthrough();
                }

                if (settings.IsPasswordFlowAllowed)
                {
                    options.AllowPasswordFlow();    
                }

                if (!settings.IsRefreshTokenFlowDisabled)
                {
                    options.AllowRefreshTokenFlow();
                }
            }
        );
    }
}