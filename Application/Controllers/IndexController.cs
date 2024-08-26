using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Application.Controllers;

public class IndexController : BaseController
{
    public IndexController()
    {
    }

    [HttpGet("index")]
    public string Index()
    {
        return "Ok";
    }
}