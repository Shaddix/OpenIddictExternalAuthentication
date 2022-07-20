using Shaddix.OpenIddict.ExternalAuthentication.Example.Controllers;
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
}
