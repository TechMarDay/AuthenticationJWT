using AuthenticationJWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace AuthenticationJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] UserLoginModel userLogin)
        {
            UserLoginModel user = null;
            if (userLogin.UserName == "UserTest")
                user = new UserLoginModel
                {
                    UserName = "UserTest",
                    PassWord = "UserTest",
                    Gender = "male"
                };

            if (user == null)
                return BadRequest("Sai tên đăng nhập hoặc mật khẩu. Vui lòng thử lại");

            var accessToken = GenerateToken(user);

            return Ok(accessToken);
        }

        [Authorize("jwtAuthen")]
        [HttpGet("profile")]
        public IActionResult GetUserProfileAsync()
        {
            var currentUser = HttpContext.User;

            var userProfile = new UserLoginModel();

            if (currentUser.HasClaim(x => x.Type == ClaimTypes.Gender))
            {
                userProfile.Gender = currentUser.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Gender).Value;
            }

            if (currentUser.HasClaim(x => x.Type == ClaimTypes.NameIdentifier))
            {
                userProfile.UserName = currentUser.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value;
            }

            return Ok($"Authorize thành công bởi user {userProfile.UserName} có giới tính {userProfile.Gender}");
        }

        private string GenerateToken(UserLoginModel userLogin)
        {
            //Payload chứa các claims là các thông tin muốn có trong token. Ví dụ như: username, userId, phone... tùy theo nhu cầu của ứng dụng.
            var claims = new[]
            {
                 new Claim(JwtRegisteredClaimNames.Sub, userLogin.UserName),
                 new Claim(JwtRegisteredClaimNames.Gender, userLogin.Gender)
            };

            //Phải giống TokenValidationParameters trong startup.cs config
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thereistechmardaykeysecret"));
            var credentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken("issuer",
              "audient",
              claims: claims,
              expires: DateTime.Now.AddDays(1),
              signingCredentials: credentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(token);

            return encodedJwt;
        }

    }
}