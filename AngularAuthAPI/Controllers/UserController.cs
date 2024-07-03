using AngularAuth.API.ContextDB;
using AngularAuth.API.UtilityService;
using AngularAuth.BL.Interface;
using AngularAuth.Common.Helpers;
using AngularAuth.Common.Model;
using AngularAuth.Common.Model.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserBL _userBL;
        private readonly AppDbContext _appDbContext;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public UserController(AppDbContext appDbContext, IUserBL userBL, IConfiguration configuration, IEmailService emailService)
        {
            _appDbContext = appDbContext;
            _userBL = userBL;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost("login")]
        public async Task<ServiceResponse> Login([FromBody] User user)
        {
            var res = new ServiceResponse();
            try
            {
                var token = string.Empty;
                var data = await _appDbContext.Users
                    .FirstOrDefaultAsync(obj => obj.Username == user.Username);

                if( PasswordHasher.VerifyPassword(user.Password, data.Password))
                {
                    token = CreateJwt(data);
                }
                else
                {
                    res.Success = false;
                    res.Message = "Username or password incorrect";
                    return res;
                }

                data.RefreshToken = CreateRefreshToken();
                data.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
                await _appDbContext.SaveChangesAsync();

                res.Data = new TokenApiDto()
                {
                    AccessToken = token,
                    RefreshToken = data.RefreshToken
                };
                return res;
            }
            catch (Exception ex)
            {
                res.Success = false;
                res.Message = ex.Message;
                return res;
            }
        }

        [HttpPost("register")]
        public async Task<ServiceResponse> Register([FromBody] User user)
        {
            var res = new ServiceResponse();
            try
            {
                await ValidateBeforeSave(user, res);
                if(!res.Success)
                {
                    return res;
                }

                user.Password = PasswordHasher.HashPassword(user.Password);
                user.Token = "";

                await _appDbContext.AddAsync<User>(user);
                await _appDbContext.SaveChangesAsync();

                return res;
            }
            catch (Exception ex)
            {
                res.Success = false;
                res.Message = ex.Message;
                return res;
            }
        }

        [Authorize]
        [HttpGet("get-all-user")]
        public async Task<ServiceResponse> GetAllUser()
        {
            var res = new ServiceResponse();
            res.Data = await _appDbContext.Users.ToListAsync();
            return res;
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if(tokenApiDto is null)
            {
                return BadRequest("Invalid Client Request");
            }
            var principal = GetClaimsFromExpiredToken(tokenApiDto.AccessToken);
            var username = principal.Identity.Name;
            var user = await _appDbContext.Users.FirstOrDefaultAsync(user => user.Username == username);
            if(user is null || user.RefreshToken != tokenApiDto.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid Request");
            }
            var newAccessToken = CreateJwt(user);
            user.RefreshToken = CreateRefreshToken();
            await _appDbContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = user.RefreshToken
            });
        }

        [HttpPost("send-email/{email}")]
        public async Task<ServiceResponse> SendEmail(string email)
        {
            var res = new ServiceResponse();
            var user = await _appDbContext.Users.FirstOrDefaultAsync(user => user.Email == email);
            if(user is null)
            {
                res.Success = false;
                res.Message = "Email doesn't exist";
                return res;
            }
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordExpiry = DateTime.Now.AddMinutes(10);
            string from = _configuration["EmailConfig:From"];
            var emailModel = new EmailModel(email, "Reset Password", EmailBody.EmailStringBody(email, emailToken));
            _emailService.SendEmail(emailModel);
            _appDbContext.Entry(user).State = EntityState.Modified;
            await _appDbContext.SaveChangesAsync();
            return res;
        }

        [HttpPost("reset-password")]
        public async Task<ServiceResponse> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            var res = new ServiceResponse();
            var newToken = resetPasswordDto.EmailToken.Replace(" ", "+");
            var user = await _appDbContext.Users.AsNoTracking().FirstOrDefaultAsync(user => user.Email == resetPasswordDto.Email);
            if (user is null)
            {
                res.Success = false;
                res.Message = "User doesn't exist";
                return res;
            }

            var tokenCode = user.ResetPasswordToken;
            DateTime emailTokenExpiry = user.ResetPasswordExpiry;
            if(tokenCode != resetPasswordDto.EmailToken || emailTokenExpiry < DateTime.Now)
            {
                res.Success = false;
                res.Message = "Invalid reset link";
                return res;
            }
            user.Password = PasswordHasher.HashPassword(resetPasswordDto.NewPassword);
            _appDbContext.Entry(user).State = EntityState.Modified;
            await _appDbContext.SaveChangesAsync();
            return res;
        }

        /// <summary>
        /// Validate dữ liệu trước khi save
        /// </summary>
        /// <param name="user"></param>
        /// <param name="res"></param>
        /// <returns></returns>
        private async Task ValidateBeforeSave(User user, ServiceResponse res)
        {
            if (user == null)
            {
                res.Success = false;
            }

            // Check username
            if (await CheckUserNameExistAsync(user.Username))
            {
                res.Success = false;
                res.Message = "Duplicate username";
            }

            // Check Email
            if (await CheckEmailExistAsync(user.Email))
            {
                res.Success = false;
                res.Message = "Duplicate email";
            }

            // Check password strength
            var validatePass = CheckPasswordStrength(user.Password);
            if (!string.IsNullOrWhiteSpace(validatePass))
            {
                res.Success = false;
                res.Message = validatePass;
            }
        }

        /// <summary>
        /// Kiểm tra xem password đã mạnh chưa
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private string CheckPasswordStrength(string password)
        {
            StringBuilder stringBuilder = new StringBuilder();
            if (password.Length < 8)
            {
                stringBuilder.Append("Minimum password length should be 8 " + Environment.NewLine);
            }

            if (!Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]"))
            {
                stringBuilder.Append("Password should be Alphanumeric" + Environment.NewLine);
            }

            if(!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&]"))
            {
                stringBuilder.Append("Password should contain special chars" + Environment.NewLine);
            }
            return stringBuilder.ToString();
        }

        /// <summary>
        /// Check trùng username khi đăng ký tài khoản
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private async Task<bool> CheckUserNameExistAsync(string username)
        {
            return await _appDbContext.Users.AnyAsync(user => user.Username == username);
        }

        /// <summary>
        /// Check trùng email khi đăng ký tài khoản
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private async Task<bool> CheckEmailExistAsync(string email)
        {
            return await _appDbContext.Users.AnyAsync(user => user.Email == email);
        }

        /// <summary>
        /// Tạo JWT khi login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler(); // instance dùng để read, create, validate jwt token
            var key = Encoding.ASCII.GetBytes("lqnhatprivatekeysecret.........."); // key dùng để ký
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.Username}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256); // dùng thuật toán sha256 để mã hóa key

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity, // payload
                Expires = DateTime.Now.AddSeconds(10), // thời gian hết hạn token
                SigningCredentials = credentials, // chữ ký
            };

            // Phần header đã được tạo ngầm định bởi JwtSecurityTokenHandler và SigningCredentials

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);

        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
            var tokenInUser = _appDbContext.Users.Any(user => user.RefreshToken == refreshToken);
            if(tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetClaimsFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("lqnhatprivatekeysecret.........."); // key dùng để ký
            var tokenValidationParam = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParam, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("This is invalid token");
            }
            return principal;
        }
    }
}
