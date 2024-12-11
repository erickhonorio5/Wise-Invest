using Auth.API.Data;
using Auth.API.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Auth.API.Configuration;

public static class IdentityConfig
{
    public static IServiceCollection AddIdentityConfig(this IServiceCollection services,
                  IConfiguration configuration)
    {
        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        //JWT

        var appSettingsSection = configuration.GetSection("AppSettings");
        services.Configure<AppSettings>(appSettingsSection);

        var appSettings = appSettingsSection.Get<AppSettings>();
        var key = Encoding.ASCII.GetBytes(appSettings.Secret);

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(bearerOpt =>
        {
            bearerOpt.RequireHttpsMetadata = true;
            bearerOpt.SaveToken = true;
            bearerOpt.TokenValidationParameters = new()
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = appSettings.ValidIn,
                ValidIssuer = appSettings.Issuer
            };
        });

        services.AddAuthorization();

        return services;
    }
}
