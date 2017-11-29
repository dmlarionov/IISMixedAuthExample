using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;

namespace WebApplication1
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }

        protected void Application_Error()
        {
            var currentException = Server.GetLastError();
            if (currentException != null && currentException is System.Security.Authentication.AuthenticationException)
            {
                HttpContext.Current.Server.ClearError();

                // Federative authentication by Security Token Service
                var WSFedAuthModule = (HttpContext.Current.ApplicationInstance.Modules.Get("WSFederationAuthenticationModule") as WSFederationAuthenticationModule);
                WSFedAuthModule?.RedirectToIdentityProvider("passive", HttpContext.Current.Request.RawUrl, true);
            }
        }
    }
}
