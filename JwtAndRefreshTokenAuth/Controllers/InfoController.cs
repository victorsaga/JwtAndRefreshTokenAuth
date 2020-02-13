using JwtAndRefreshTokenAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAndRefreshTokenAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InfoController : ControllerBase
    {
        private readonly IConfigService _configService;
        public InfoController(IConfigService configService)
        {
            _configService = configService;
        }

        [Authorize]
        //[AllowAnonymous]
        [HttpGet("GetExpireTime")]
        public int GetExpireTime()
        {
            return _configService.GetJwtExpireTimeMinutes();
        }
    }
}