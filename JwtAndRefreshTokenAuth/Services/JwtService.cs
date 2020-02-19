using JwtAndRefreshTokenAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAndRefreshTokenAuth
{
    public class JwtService : IJwtService
    {
        private readonly IConfigService _configService;
        private const string RefreshTokenName = "RefreshToken";
        //private const string SubjectName = "Subject";
        private static IDistributedCache _distributedCache;

        public JwtService(IConfigService configService)
        {
            _configService = configService;
        }

        public JwtService(IConfigService configService, IDistributedCache distributedCache)
        {
            _configService = configService;
            _distributedCache = distributedCache;
        }

        public string CreateJwtToken(string userName, Dictionary<string, string> payload, string signKey, DateTime expireTime, DateTime? refreshExpireTime = null)
        {
            if (string.IsNullOrEmpty(signKey) || signKey.Length < 16)
                throw new Exception("'signKey' must >= 16 chars");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            if (payload == null)
                payload = new Dictionary<string, string>();

            if (refreshExpireTime != null)
            {
                var refreshToken = Guid.NewGuid().ToString("N");
                AddRefreshTokenToCache(refreshToken, refreshExpireTime.Value);

                payload[RefreshTokenName] = refreshToken;
            }

            payload[JwtRegisteredClaimNames.Sub] = userName;
            var claims = payload.Select(x => new Claim(x.Key, x.Value)).ToList();

            var token = new JwtSecurityToken(
                claims: claims,
                expires: expireTime,
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public bool VerifyJWT(string token, string signKey, out Dictionary<string, object> outPayload)
        {
            outPayload = new Dictionary<string, object>();

            //檢查簽章是否正確
            ClaimsPrincipal cp;
            try
            {
                SecurityToken validatedToken;
                cp = new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey))
                }, out validatedToken);

                //解 Payload                   
                outPayload = cp.Claims.ToDictionary(x => x.Type, y => (object)y.Value);
            }
            catch
            {
                //Incorrect JWT format
                cp = null;
            }
            return cp != null;
        }

        private static object LockRefreshTokenCache = new object();
        public string RefreshToken(string token, string signKey, DateTime expireTime, DateTime? refreshExpireTime = null)
        {
            var newToken = "";
            try
            {
                string decodedString = GetJwtPayloadStringFromBase64(token);
                if (string.IsNullOrEmpty(decodedString))
                    return newToken;

                var payloadDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(decodedString);

                if (payloadDic.ContainsKey(RefreshTokenName))
                {
                    var currentRefreshKey = payloadDic[RefreshTokenName];

                    //avoid token refresh multiple times
                    lock (LockRefreshTokenCache)
                    {
                        //check refresh token
                        if (!IsExistsRefreshTokenCache(currentRefreshKey))
                            return newToken;
                        //create new token
                        newToken = CreateJwtToken(payloadDic[JwtRegisteredClaimNames.Sub], payloadDic, signKey, expireTime, refreshExpireTime);

                        //delete current refresh token 
                        RemoveRefreshTokenCache(currentRefreshKey);
                    }
                }
            }
            catch (Exception e)
            {
                //todo: write log
            }
            return newToken;
        }

        public void AddJwtAuthentication(IServiceCollection services)
        {
            services
              .AddAuthentication(s =>
              {
                  //添加JWT Scheme
                  s.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                  s.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                  s.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
              })   // 檢查 HTTP Header 的 Authorization 是否有 JWT Bearer Token           
              .AddJwtBearer(options => //JWT驗證的參數
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero, //時間偏移容忍範圍，預設為300秒
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configService.GetJwtKey()))
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {  //Token expired                          
                            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                                context.Response.Headers.Add("Token-Expired", "true");
                            return Task.CompletedTask;
                        }
                    };
                });
        }

        private string GetJwtPayloadStringFromBase64(string token)
        {
            var base64Payload = token.Split('.')[1];
            var appendCount = 4 - (base64Payload.Length % 4);
            if (appendCount > 0 && appendCount < 4)
                base64Payload += string.Concat(Enumerable.Repeat('=', appendCount));

            byte[] data = Convert.FromBase64String(base64Payload);
            return Encoding.UTF8.GetString(data);
        }



        private void AddRefreshTokenToCache(string refreshToken, DateTime expireTime)
            => _distributedCache.SetString(GetRefreshTokenCacheName(refreshToken),
                                                                            expireTime.ToString(),
                                                                            GetdistributedCacheEntryOptions(expireTime));

        private bool IsExistsRefreshTokenCache(string refreshToken)
            => !string.IsNullOrEmpty(_distributedCache.GetString(GetRefreshTokenCacheName(refreshToken)));

        private void RemoveRefreshTokenCache(string refreshToken)
            => _distributedCache.Remove(GetRefreshTokenCacheName(refreshToken));

        private string GetRefreshTokenCacheName(string refreshToken)
            => $"{RefreshTokenName}Cache:{refreshToken}";

        private DistributedCacheEntryOptions GetdistributedCacheEntryOptions(DateTime expireTime)
            => new DistributedCacheEntryOptions { AbsoluteExpiration = expireTime };
    }
}
