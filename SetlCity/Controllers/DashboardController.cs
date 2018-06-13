using System.Web.Mvc;
using SetlCity.Models;

namespace SetlCity.Controllers
{
    [CheckAuthorization]
    public class DashboardController : Controller
    {
        // GET: Dashboard
        public ActionResult Index()
        {
            return View();
        }
    }
}