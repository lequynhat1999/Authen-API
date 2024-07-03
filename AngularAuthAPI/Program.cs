using AngularAuth.BL;
using AngularAuth.BL.Interface;
using AngularAuth.API.ContextDB;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AngularAuth.API.UtilityService;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(option =>
{
    option.AddPolicy("MyPolicy", builder =>
    {
        builder.AllowAnyHeader().AllowAnyOrigin().AllowAnyMethod();
    });
});
builder.Services.AddDbContext<AppDbContext>(option =>
{
    option.UseSqlServer(builder.Configuration.GetConnectionString("SqlServerConnStr"));
});

builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // mặc định sẽ sử dụng JWT để validate
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; // nếu có validate request thì sẽ sử dụng JWT
}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false; // disable việc validate cho request HTTPS
    x.SaveToken = true; // lưu token vào HttpContext để cache lại
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true, // đảm bảo token hợp lệ
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("lqnhatprivatekeysecret..........")),  // dùng key để mã hóa
        ValidateAudience = false, // tắt xác thực đối tượng
        ValidateIssuer = false,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddScoped<IUserBL, UserBL>();
builder.Services.AddScoped<IEmailService, EmailServiceBL>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("MyPolicy");

app.UseAuthentication(); // enable authentication middleware

app.UseAuthorization();

app.MapControllers();

app.Run();
