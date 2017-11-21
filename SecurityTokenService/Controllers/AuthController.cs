﻿using System.Web.Mvc;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.Security.Principal;
using Security.SimpleWebToken;

namespace SecurityTokenService.Controllers
{
    public class AuthController : Controller
    {
        //
        // GET: /Auth/Login
        public ActionResult Login()
        {
            var action = Request.QueryString[SecurityTokenServiceConstants.WSFederation.Parameters.Action];
            var returnUrl = Request.QueryString[SecurityTokenServiceConstants.WSFederation.Parameters.WReply];
            
            if (action == SecurityTokenServiceConstants.WSFederation.Actions.SignIn)
            {
                // setup principal
                ClaimsPrincipal principal = new ClaimsPrincipal(new ClaimsIdentity());

                // generate token
                var requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri(Request.Url);
                var config = SecurityTokenServiceConfigurationUtility.CreateConfigurationFromExpectedUrl(requestMessage.Realm);
                var sts = new MySecurityTokenService(config);
                var responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, principal, sts);
                return new ContentResult() { Content = responseMessage.WriteFormPost(), ContentType = "text/html" };
            }

            if (returnUrl != null)
                return Redirect(returnUrl);
            else
                return new ContentResult() { Content = string.Empty, ContentType = "text/html" };
        }
    }
}