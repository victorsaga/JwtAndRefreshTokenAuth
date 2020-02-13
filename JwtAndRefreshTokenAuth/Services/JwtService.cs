using JwtAndRefreshTokenAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAndRefreshTokenAuth
{
    public class JwtService : IJwtService
    {
        private readonly IConfigService _configService;
        private const string RefreshTokenName = "RefreshToken";
        private const string SubjectName = "Subject";
        private static IDistributedCache _distributedCache;
        //private Dictionary<string, DateTime> refreshTokens = new Dictionary<string, DateTime>();

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
                AppendRefreshTokenDictionary(refreshToken, refreshExpireTime.Value);

                payload.Add(RefreshTokenName, refreshToken);
            }

            var claims = payload.Select(x => new Claim(x.Key, x.Value)).ToList();
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userName));

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
                    //get from cache
                    var refreshTokens = GetRefreshTokenDictionary();
                    if (!refreshTokens.ContainsKey(currentRefreshKey))
                        return newToken;

                    var currentRefreshExpireTime = refreshTokens[currentRefreshKey];
                    if (currentRefreshExpireTime != null && currentRefreshExpireTime > DateTime.Now)
                    {
                        payloadDic.Remove(RefreshTokenName);
                        newToken = CreateJwtToken(payloadDic[SubjectName], payloadDic, signKey, expireTime, refreshExpireTime);
                        //刪除此次的refresh token & 過期的refresh token
                        var deleteKeys = refreshTokens.Where(x => x.Key == currentRefreshKey || x.Value <= DateTime.Now).Select(x => x.Key).ToList();
                        foreach (var item in deleteKeys)
                            refreshTokens.Remove(item);

                        //update to cache
                        SetRefreshTokenDictionary(refreshTokens);
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
              .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)   // 檢查 HTTP Header 的 Authorization 是否有 JWT Bearer Token           
              .AddJwtBearer(options => //JWT驗證的參數
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = true,
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
            if (appendCount > 0)
                base64Payload += string.Concat(Enumerable.Repeat('=', appendCount));

            byte[] data = Convert.FromBase64String(base64Payload);
            return Encoding.UTF8.GetString(data);
        }


        private static object LockRefreshTokenCache = new object();

        private Dictionary<string, DateTime> GetRefreshTokenDictionary()
        {
            lock (LockRefreshTokenCache)
            {
                var bytes = _distributedCache.Get(RefreshTokenName + "Cache");
                return bytes == null
                                ? new Dictionary<string, DateTime>()
                                : ByteArrayToObject<Dictionary<string, DateTime>>(bytes);
            }
        }

        private void SetRefreshTokenDictionary(Dictionary<string, DateTime> refreshToken)
        {
            lock (LockRefreshTokenCache)
                _distributedCache.Set(RefreshTokenName + "Cache", ObjectToByteArray(refreshToken));
        }

        private void AppendRefreshTokenDictionary(string key, DateTime value)
        {
            lock (LockRefreshTokenCache)
            {
                var dic = GetRefreshTokenDictionary();
                dic.Add(key, value);
                SetRefreshTokenDictionary(dic);
            }
        }

        private byte[] ObjectToByteArray(object obj)
        {
            var binaryFormatter = new BinaryFormatter();
            using (var memoryStream = new MemoryStream())
            {
                binaryFormatter.Serialize(memoryStream, obj);
                return memoryStream.ToArray();
            }
        }

        private T ByteArrayToObject<T>(byte[] bytes)
        {
            using (var memoryStream = new MemoryStream())
            {
                var binaryFormatter = new BinaryFormatter();
                memoryStream.Write(bytes, 0, bytes.Length);
                memoryStream.Seek(0, SeekOrigin.Begin);
                var obj = binaryFormatter.Deserialize(memoryStream);
                return (T)obj;
            }
        }
    }
}
