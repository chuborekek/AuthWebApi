using AuthWebApi.Data;
using AuthWebApi.Helpers;
using AuthWebApi.Interfaces;
using AuthWebApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<AppDbContext>(
    opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

//for authentication using JWT
var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig:Secret").Value);
var tokenValidationParameter= new TokenValidationParameters()
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false, //for dev
    ValidateAudience = false, //for development purpose
    RequireExpirationTime = false,//tru if for production already, need to be updated when refresh token is added
    ClockSkew = TimeSpan.Zero,

};
builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(jwt =>
{  
    jwt.SaveToken=true;
    jwt.TokenValidationParameters = tokenValidationParameter;
});
builder.Services.AddSingleton(tokenValidationParameter);

//for sending Email using SendGrid
builder.Services.AddTransient<ISendGridEmail, SendGridEmail>();
builder.Services.Configure<AuthMessageSenderOptions>(builder.Configuration.GetSection("SendGrid"));


//for IdentityUser Configuration
builder.Services.AddIdentity<IdentityUser, IdentityRole>(opt => opt.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<AppDbContext>().AddDefaultTokenProviders();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
