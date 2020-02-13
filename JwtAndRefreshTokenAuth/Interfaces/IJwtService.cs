using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;

namespace JwtAndRefreshTokenAuth
{
    public interface IJwtService
    {
        void AddJwtAuthentication(IServiceCollection services);
        string CreateJwtToken(string userName, Dictionary<string, string> payload, string signKey, DateTime expireTime, DateTime? refreshExpireTime = null);
        string RefreshToken(string token, string signKey, DateTime expireTime, DateTime? refreshExpireTime = null);
        bool VerifyJWT(string token, string signKey, out Dictionary<string, object> outPayload);
    }
}