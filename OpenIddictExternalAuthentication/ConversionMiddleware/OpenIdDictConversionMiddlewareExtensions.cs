using Microsoft.AspNetCore.Builder;

public static class OpenIdDictConversionMiddlewareExtensions
{
    public static IApplicationBuilder UseOpenIdDictConversionMiddleware(
        this IApplicationBuilder builder,
        OpenIdDictConversionSettings settings
    )
    {
        return builder.UseMiddleware<OpenIdDictConversionMiddleware>(settings);
    }
}