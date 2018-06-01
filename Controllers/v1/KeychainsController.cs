using BTBaseServices;
using Microsoft.AspNetCore.Mvc;

[Route("api/v1/[controller]")]
public class KeychainsController
{
    [HttpGet("{algorithm}")]
    public object GenerateNewKeychain(string algorithm)
    {
        //Supported Alogrithm:
        //SecurityKeychainSymmetricsExtensions.ALGORITHM_SYMMETRIC="Symmetric"
        //SecurityKeychainRSAExtensions.ALGORITHM_RSA="RSA"
        var keychain = SecurityKeychainProvider.Create("Temp", algorithm, "Temp Keychain");
        return new { pubkey = keychain.PublicKey, prikey = keychain.PrivateKey, algorithm = keychain.Algorithm };
    }
}