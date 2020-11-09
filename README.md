# AuthenticationJWT
https://techmarday.com/jwt-authentication-dotnet-core

1. JWT là gì?

JWT viết tắt cho json web token là 1 chuỗi token có định dạng json để truyền thông tin an toàn giữa client và server.
JWT an toàn là dựa vào chữ ký của nó sẽ được mã hóa bằng các thuật toán mã hóa. 

2. Cấu trúc JWT

Header có 2 phần. 1 là typ chỉ ra type là "JWT" và 2 là thuật toán mã hóa algorithm (ví dụ HS256)
Payload chứa các claims là các thông tin muốn có trong token. Ví dụ như: username, userId, phone... tùy theo nhu cầu của ứng dụng.
Lưu ý: Có 1 số thông tin metadata bắt buộc phải có của claims như:  iss (issuer), iat (issued-at time) exp (expiration time), sub (subject), aud (audience)...
Không nên chứa quá nhiều thông tin trong claims sẽ khiến chuỗi token dài và chậm khi tạo ra và load lên.
Signature là 1 chuỗi mã hóa bao gồm header, payload và 1 chuỗi bí mật (secret).

Kết hợp cả 3 chuỗi lại ta sẽ có được token.
Ví dụ 1 chuỗi token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pblRlc3QiLCJqdGkiOiI0NjRhODc4YS02MzkxLTRiM2UtYjI0NC1jYzZi

3. Tại sao lại dùng JWT

Dùng JWT an toàn vì có phần chữ ký được mã hóa bao gồm header, payload nên sẽ không giả mạo được chữ ký.
Dùng JWT để authentication có thể sử dụng cho cả ứng dụng web, mobile và các service khác nhau. JWT tốt hơn cookie cho ứng dụng mobile.
Không bị Cross-origin resource sharing (Cors) như khi dùng cookie authentication

4. JWT Authentication  trong .net core

Tạo mới project:





Thêm Swagger cho api:

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Stylist app API", Version = "v1" });

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Name = "Bearer",
                            In = ParameterLocation.Header
                        },
                        new List<string>()
                    }
                });
            });
        }
Thêm authentication

 services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
             .AddJwtBearer(options =>
             {
                 options.SaveToken = true;
                 options.TokenValidationParameters = new TokenValidationParameters
                 {
                     ValidateIssuer = true,
                     ValidIssuer = "issuer", // Nên config trong appsetting

                     ValidateAudience = true,
                     ValidAudience = "audient", // Nên config trong appsetting

                     ValidateIssuerSigningKey = true,
                     IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thereistechmardaykeysecret")), // Nên config trong appsetting

                     ValidateLifetime = true
                 };
             });

            services.AddAuthorization(options =>
            options.AddPolicy("jwtAuthen", policy =>
            {
                policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
            }));
Tạo access token. Các claims được gắn vào token sẽ được dùng tùy theo mục đích khác nhau. Như bên dưới có 2 thông tin là userName và Gender sẽ được lưu vào claims => sau đó sẽ được lấy ra ở HttpContext.User

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
Token sẽ được tạo ra mỗi khi login. Lưu ý phương thức login phải là AllowAnonymous
 

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
Test token và kiểm tra thông tin claims ở trên.
 

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

Source code trên github: https://github.com/TechMarDay/AuthenticationJWT
