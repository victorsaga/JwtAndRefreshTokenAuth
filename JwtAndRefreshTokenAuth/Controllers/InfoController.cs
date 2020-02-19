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
        [HttpGet("GetExpireTime")]
        public int GetExpireTime()
        {
            return _configService.GetJwtExpireTimeMinutes();
        }


        [AllowAnonymous]
        [HttpGet("GetExpireTime2")]
        public int GetExpireTime2()
        {
            return _configService.GetJwtExpireTimeMinutes();
        }
    }
}