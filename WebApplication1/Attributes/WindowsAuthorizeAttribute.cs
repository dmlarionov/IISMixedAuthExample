using System;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Mvc;

namespace WebApplication1.Attributes
{
    /* 
     * NOT USED TO IMPLEMENT MIXED AUTH
     * I keep it here just for example of how attribute can be customized
     */
    
    /// <summary>
    /// Experimental attribute, that specifies controller or action method windows-only authentication
    /// </summary>
    public class WindowsAuthorizeAttribute : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
                throw new ArgumentNullException(nameof(httpContext));

            IIdentity identity = Thread.CurrentPrincipal.Identity;

            if (!identity.IsAuthenticated || identity.AuthenticationType != "Negotiate" && identity.AuthenticationType != "NTLM")
            {
                httpContext.User = null;
                return false;
            }
            else
                return base.AuthorizeCore(httpContext);
        }
    }
}