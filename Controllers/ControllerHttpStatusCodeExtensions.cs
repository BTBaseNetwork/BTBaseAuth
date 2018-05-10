using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace BTBaseAuth.Controllers
{
    public static class ControllerHttpStatusCodeExtensions
    {
        public static int SetResponseStatusCode(this Controller controller, int statusCode)
        {
            controller.Response.StatusCode = statusCode;
            return statusCode;
        }

        public static int SetResponseStatusCode(this Controller controller, HttpStatusCode statusCode)
        {
            return controller.SetResponseStatusCode((int)statusCode);
        }

        public static int SetResponseOK(this Controller controller)
        {
            return SetResponseStatusCode(controller, HttpStatusCode.OK);
        }

        public static int SetResponseForbidden(this Controller controller)
        {
            return SetResponseStatusCode(controller, HttpStatusCode.Forbidden);
        }

        public static int SetResponseNotFound(this Controller controller)
        {
            return SetResponseStatusCode(controller, HttpStatusCode.NotFound);
        }
    }
}