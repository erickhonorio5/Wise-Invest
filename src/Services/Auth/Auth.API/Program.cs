using Auth.API.Configuration;
using Auth.API.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() 
    { 
        Title = "Auth.API", Version = "v1" ,
        Description = "API de autenticação"
    });
});

var connectionStringKey = builder.Environment.IsDevelopment()
    ? Environment.GetEnvironmentVariable("ASPNETCORE_DOCKER") == "true"
        ? "ConnectionDocker"
        : "DefaultConnection"
        : "DefaultConnection";

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString(connectionStringKey)));

builder.Services.AddIdentityConfig(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => 
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth.API v1");
    });
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();

