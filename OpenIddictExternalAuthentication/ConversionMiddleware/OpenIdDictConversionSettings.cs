using System.Collections.Generic;

public class OpenIdDictConversionSettings
{
    public List<string> ScopesToRemove { get; set; } = new() { "profile" };

    public Dictionary<string, string> ParamsToRename { get; set; } =
        new() { { "userName", "username" } };

    public bool ShouldRemoveClientSecretForPublicClients { get; set; } = true;

    public bool ShouldRemoveAuthorizationHeaderIfClientIdOrClientSecretIsPresent { get; set; } =
        true;
}
