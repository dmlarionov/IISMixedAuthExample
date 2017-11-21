using System;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.Security.Claims;


namespace SecurityTokenService
{
    /// <summary>
    /// Overrides the SecurityTokenService class to provide
    /// the relying party related information, such as encryption credentials to encrypt the issued
    /// token, signing credentials to sign the issued token, claims that the STS wants to issue for a 
    /// certain token request, as well as the claim types that this STS is capable
    /// of issuing.
    /// </summary>
    public class MySecurityTokenService : System.IdentityModel.SecurityTokenService
    {
        public MySecurityTokenService(SecurityTokenServiceConfiguration configuration)
            : base(configuration)
        {
        }


        /// <summary>
        /// This method returns the configuration for the token issuance request. The configuration
        /// is represented by the Scope class. In our case, we are only capable of issuing a token to a
        /// single RP identity represented by the _encryptingCreds field.
        /// </summary>
        /// <param name="principal">The caller's principal</param>
        /// <param name="request">The incoming RST</param>
        /// <returns></returns>
        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            // Validate the AppliesTo address
            ValidateAppliesTo(request.AppliesTo);

            // Create the scope using the request AppliesTo address and the RP identity
            var scope = new Scope(request.AppliesTo.Uri.AbsoluteUri, SecurityTokenServiceConfiguration.SigningCredentials);

            if (Uri.IsWellFormedUriString(request.ReplyTo, UriKind.Absolute))
            {
                if (request.AppliesTo.Uri.Host != new Uri(request.ReplyTo).Host)
                    scope.ReplyToAddress = request.AppliesTo.Uri.AbsoluteUri;
                else
                    scope.ReplyToAddress = request.ReplyTo;
            }
            else
            {
                Uri resultUri = null;
                if (Uri.TryCreate(request.AppliesTo.Uri, request.ReplyTo, out resultUri))
                    scope.ReplyToAddress = resultUri.AbsoluteUri;
                else
                    scope.ReplyToAddress = request.AppliesTo.Uri.ToString();
            }

            scope.TokenEncryptionRequired = false;

            return scope;
        }

        /// <summary>
        /// This method returns the content of the issued token. The content is represented as a set of
        /// IClaimIdentity intances, each instance corresponds to a single issued token. Currently, the Windows Identity Foundation only
        /// supports a single token issuance, so the returned collection must always contain only a single instance.
        /// </summary>
        /// <param name="scope">The scope that was previously returned by GetScope method</param>
        /// <param name="principal">The caller's principal</param>
        /// <param name="request">The incoming RST, we don't use this in our implementation</param>
        /// <returns></returns>
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            //
            // Return a default claim set which contains a custom decision claim
            // Here you can actually examine the user by looking at the IClaimsPrincipal and 
            // return the right decision based on that. 
            //
            var outgoingIdentity = new ClaimsIdentity();
            outgoingIdentity.AddClaims(principal.Claims);

            return outgoingIdentity;
        }

        /// <summary>
        /// Validates the appliesTo and throws an exception if the appliesTo is null or appliesTo contains some unexpected address.
        /// </summary>
        /// <param name="appliesTo">The AppliesTo parameter in the request that came in (RST)</param>
        /// <returns></returns>
        private void ValidateAppliesTo(EndpointReference appliesTo)
        {
            if (appliesTo == null)
            {
                throw new InvalidRequestException("The appliesTo is null.");
            }
        }

    }
}