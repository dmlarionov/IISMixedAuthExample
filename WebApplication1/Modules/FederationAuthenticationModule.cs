using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Web;
using WebApplication1.Configuration.FederationAuthenticationExclusions;

namespace WebApplication1.Modules
{
    public class FederationAuthenticationModule : WSFederationAuthenticationModule
    {
        protected override void OnEndRequest(object sender, EventArgs args)
        {
            HttpApplication httpApplication = (HttpApplication)sender;
            foreach (Item item in Section.Default.Items)
            {
                if (httpApplication.Request.RawUrl.StartsWith(item.Url, StringComparison.InvariantCultureIgnoreCase))
                    return;
            }
            base.OnEndRequest(sender, args);
        }
    }
}