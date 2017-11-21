using System;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using Security.SimpleWebToken;
using System.Text;

namespace SecurityTokenService
{
    public class SecurityTokenServiceConfigurationUtility
    {
        private const string SymmetricKeySignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
        private const string SymmetricKeyDigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

        public static SecurityTokenServiceConfiguration CreateConfigurationFromExpectedUrl(string url)
        {
            var config = new SecurityTokenServiceConfiguration();
            config.TokenIssuerName = "sts.test.larionov";                           // hard-coded for testing purposes only !
            config.SecurityTokenService = typeof(MySecurityTokenService);
            config.DefaultTokenLifetime = TimeSpan.FromHours(2);
            config.SecurityTokenHandlers.Add(new SimpleWebTokenHandler());
            config.DefaultTokenType = SimpleWebTokenHandler.SimpleWebTokenTypeUri;
            config.SigningCredentials = new SigningCredentials(new InMemorySymmetricSecurityKey(
                Encoding.UTF8.GetBytes("wAVkldQiFypTQ+ddNdGWCBCHRcee9XmXxXvgmak8vSDm")),      // hard-coded for testing purposes only !
                SymmetricKeySignatureAlgorithm,
                SymmetricKeyDigestAlgorithm);

            return config;
        }
    }
}