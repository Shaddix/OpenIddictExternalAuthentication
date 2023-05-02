using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Shaddix.OpenIddict.ExternalAuthentication.Example.Controllers;
using Shaddix.OpenIddict.ExternalAuthentication.IdentityServerMigrator;
using Xunit;

namespace OpenIddictExternalAuthentication.Tests;

public class UnitTest1
{
    [Theory]
    [InlineData(
        "?client_id=web_client&redirect_uri=https%3A%2F%2Flocalhost%3A5001%2Findex.html%3Fauth-callback%3D1&response_type=code&scope=offline_access&state=...&code_challenge=...&code_challenge_method=S256&response_mode=query&prompt=login&display=popup&provider=Google",
        "?client_id=web_client&redirect_uri=https%3A%2F%2Flocalhost%3A5001%2Findex.html%3Fauth-callback%3D1&response_type=code&scope=offline_access&state=...&code_challenge=...&code_challenge_method=S256&response_mode=query&prompt=login&display=popup&provider=Google"
    )]
    [InlineData("/", "/")]
    [InlineData("/asd/zxc", "/asd/zxc")]
    [InlineData("/asd/zxc?qwe=123", "/asd/zxc?qwe=123")]
    [InlineData("/asd/zxc?qwe=123&provider=Google", "/asd/zxc?qwe=123&provider=Google")]
    [InlineData(null, "")]
    [InlineData("", "")]
    public void AdjustReturnUrl(string returnUrl, string expectedResult)
    {
        Assert.Equal(
            expectedResult,
            AuthorizationController.AdjustReturnUrl(returnUrl, "Google"),
            ignoreCase: true
        );
    }

    [Fact]
    public void EncodeRefreshToken()
    {
        var input = "0DC92BC934F7107BB8B4C4D2BD78E5B0DC800A4D01657642E8ECA0ABC10A2205-1";
        var result = IdentityServerRefreshTokenValidator<DbContext>.GetHashedKey(input);
        Assert.Equal("5822724F41371C9CE0BC25AC1B4EEEB9C978F356D7DF8DD9AE43F83137C4A3E9", result);
    }
}
