using System;
using System.Web.Mvc;
using WebApplication1.Attributes;

namespace WebApplication1.Controllers
{
    public class TestController : Controller
    {
        // GET: Test/Open - allow any users, authenticated and not
        public ActionResult Open()
        {
            return View("AuthInfo");
        }

        // GET: Test/WinAuth1 - protected location in web.config
        public ActionResult WinAuth1()
        {
            return View("AuthInfo");
        }

        // GET: Test/WinAuth2 - protected by MVC attribute
        [Authorize]
        public ActionResult WinAuth2()
        {
            return View("AuthInfo");
        }

        // GET: Test/FedAuth1 - protected location in web.config
        public ActionResult FedAuth1()
        {
            return View("AuthInfo");
        }

        // GET: Test/FedAuth2 - protected by standard MVC attribute
        [Authorize]
        public ActionResult FedAuth2()
        {
            return View("AuthInfo");
        }
    }
}