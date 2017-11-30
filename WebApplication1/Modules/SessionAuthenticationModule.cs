using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Web;
using WebApplication1.Configuration.FederationAuthenticationExclusions;

namespace WebApplication1.Modules
{
    public class SessionAuthenticationModule : System.IdentityModel.Services.SessionAuthenticationModule
    {
        protected override void OnAuthenticateRequest(object sender, EventArgs eventArgs)
        {
            HttpApplication httpApplication = (HttpApplication)sender;

            // step over federative authentication if URL in federationAuthenticationExclusions section of Web.config
            foreach (Item item in Section.Default.Items)
            {
                if (httpApplication.Request.RawUrl.StartsWith(item.Url, StringComparison.InvariantCultureIgnoreCase))
                    return;
            }

            IIdentity identity = Thread.CurrentPrincipal.Identity;

            // in case of federative authentication (URL not in exclusions)
            // if user is authenticated, but it is not federative authentication, reset authentication
            if (identity.IsAuthenticated || identity.AuthenticationType != "Federation")
            {
                httpApplication.Context.User = null;
            }

            // if user is not authenticated, try to authenticate as usual by FedAuth cookie
            base.OnAuthenticateRequest(sender, eventArgs);
        }
    }
}