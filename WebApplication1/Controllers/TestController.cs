using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace WebApplication1.Controllers
{
    public class TestController : Controller
    {
        // GET: Test/Open
        public ActionResult Open()
        {
            return View("AuthInfo");
        }

        // GET: Test/WinAuth
        public ActionResult WinAuth()
        {
            return View("AuthInfo");
        }

        // GET: Test/FedAuth1
        [Authorize]
        public ActionResult FedAuth1()
        {
            return View("AuthInfo");
        }

        // GET: Test/FedAuth2
        public ActionResult FedAuth2()
        {
            if (!ClaimsPrincipal.Current.Identity.IsAuthenticated)
                throw new AuthenticationException();
            return View("AuthInfo");
        }


        // GET: Test/FedAuth3
        public ActionResult FedAuth3()
        {
            return new HttpUnauthorizedResult();
        }
    }
}