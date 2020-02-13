namespace JwtAndRefreshTokenAuth.Services
{
    public interface IConfigService
    {
        string GetJwtKey();
        int GetJwtExpireTimeMinutes();
        int GetJwtRefreshExpireTimeMinutes();
    }
}