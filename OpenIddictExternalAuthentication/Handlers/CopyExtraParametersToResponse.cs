using System;
using System.Threading.Tasks;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

namespace Shaddix.OpenIddict.ExternalAuthentication.Handlers;

public sealed class CopyExtraParametersToResponse
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>
{
    /// <summary>
    /// Gets the default descriptor definition assigned to this handler.
    /// </summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<CopyExtraParametersToResponse>()
            .SetOrder(
                OpenIddictServerAspNetCoreHandlers
                    .Authentication
                    .ProcessQueryResponse
                    .Descriptor
                    .Order - 10
            )
            .Build();

    /// <inheritdoc/>
    public ValueTask HandleAsync(OpenIddictServerEvents.ApplyAuthorizationResponseContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var response = context.Response;
        if (response == null)
        {
            throw new ArgumentNullException(nameof(response));
        }

        var request = context.Request;
        if (request.TryGetParameter("popup", out var parameter))
            response.SetParameter("popup", parameter);

        return default;
    }
}
