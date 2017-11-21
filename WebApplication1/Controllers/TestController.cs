using System;
using System.Collections.Generic;
using System.Linq;
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

        // GET: Test/Restricted (Windows Authentication due to <authentication mode="Windows"/>)
        public ActionResult Restricted()
        {
            return View("AuthInfo");
        }

        // GET: Test/Restricted2 (Federated Authentication due to ?? NEED DIFFERENT NotAuthorized EXCEPTION PROCESSING)
        [Authorize]
        public ActionResult Restricted2()
        {
            return View("AuthInfo");
        }
    }
}