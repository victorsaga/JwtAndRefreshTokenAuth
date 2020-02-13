using Microsoft.Extensions.Configuration;

namespace JwtAndRefreshTokenAuth.Services
{
    public class ConfigService : IConfigService
    {
        private readonly IConfiguration _config;
        public ConfigService(IConfiguration config)
        {
            _config = config;
        }

        public string GetJwtKey()
            => _config.GetSection("Jwt").GetValue<string>("Key");

        public int GetJwtExpireTimeMinutes()
            => _config.GetSection("Jwt").GetValue<int>("ExpireTimeMinutes");

        public int GetJwtRefreshExpireTimeMinutes()
            => _config.GetSection("Jwt").GetValue<int>("RefreshExpireTimeMinutes");

    }
}
