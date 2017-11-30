using System;
using System.IdentityModel.Services;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Mvc;

namespace WebApplication1.Attributes
{
    /// <summary>
    /// Experimental attribute, that specifies controller or action method federated-only authentication
    /// </summary>
    public class FederativeAuthorizeAttribute : AuthorizeAttribute
    {
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            if (filterContext == null)
                throw new ArgumentNullException(nameof(filterContext));

            var httpContext = filterContext.HttpContext;
            if (httpContext == null)
                throw new NullReferenceException("filterContext.httpContext is null");

            IIdentity identity = Thread.CurrentPrincipal.Identity;

            if (!identity.IsAuthenticated || identity.AuthenticationType != "Federation")
                FederatedAuthentication.WSFederationAuthenticationModule.RedirectToIdentityProvider(
                    "passive",
                    filterContext.HttpContext.Request.RawUrl,
                    FederatedAuthentication.WSFederationAuthenticationModule.PersistentCookiesOnPassiveRedirects);
        }
    }
}