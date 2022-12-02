using AuthWebApi.Data;
using AuthWebApi.Dto;
using AuthWebApi.Interfaces;
using AuthWebApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Converters;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {

//----------------------------------------------------------Dependency Injection for Authentication Controller
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ISendGridEmail _sendGridEmail;
        private readonly AppDbContext _context;
        private readonly TokenValidationParameters _tokenValidationParameters;

        public AuthenticationController(
            UserManager<IdentityUser> userManager, 
            IConfiguration configuration,
            ISendGridEmail sendGridEmail,
            AppDbContext context,
            TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _configuration = configuration;
            _sendGridEmail = sendGridEmail;
            _context = context;
            _tokenValidationParameters = tokenValidationParameters;
        }


 //----------------------------------------------------------Registration of User 
        [Route("Register")]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto userRegistrationRequestDto)
        {   //check if the input is correct
            if (ModelState.IsValid)
            {   //check if email is already existing
                var userExist = await _userManager.FindByEmailAsync(userRegistrationRequestDto.Email);
                if (userExist != null) {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                           // $"{userExist} Email already Exist"
                           "Email already Exist"
                        }
                    });
                }
                //Code for creating a user if confirmation Email is not required
                /*
                var newUser = new IdentityUser()
                {
                    Email = userRegistrationRequestDto.Email,
                    UserName = userRegistrationRequestDto.Name,
                };
                var password = userRegistrationRequestDto.Password;
                var isCreateUser = await _userManager.CreateAsync(newUser, password);
                if (isCreateUser.Succeeded)
                {
                    var token = GenerateJwtToken(newUser);
                    return Ok(new AuthResult()
                    {
                        Result = true,
                        Token = token
                    });
                }
                */

                //Code for creating a user where confirmation Email is Required
                var newUser = new IdentityUser()
                {
                    Email = userRegistrationRequestDto.Email,
                    UserName = userRegistrationRequestDto.Name,
                    EmailConfirmed = false
                };
                var password = userRegistrationRequestDto.Password;
                var isCreateUser = await _userManager.CreateAsync(newUser, password);
                if (isCreateUser.Succeeded)
                {   //send confirmation code to email
                    await RequestToConfirmEmail(newUser.Email);
                    return Ok("User registration is successful but needs Email Confirmation.");
              

                }

                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Server Error: Something went wrong registering the user!"
                    }
                });


            }
            return BadRequest();
        }
//----------------------------------------------------------Request to Generate Token for Email Confirmation
        [Route("RequestToConfirmEmail")]
        [HttpGet]
        public async Task<IActionResult> RequestToConfirmEmail(string email)
        {
            //generate confirmation code
            var userToConfirm = await _userManager.FindByEmailAsync(email);
            if (userToConfirm != null)
            {
                //check if confirmed already
                var isUserEmailConfirmed = await _userManager.IsEmailConfirmedAsync(userToConfirm);
                if (!isUserEmailConfirmed)
                {
                    var confirmationCode = await _userManager.GenerateEmailConfirmationTokenAsync(userToConfirm);
                   
                    //-/---------------set the needed confirmation code to email of newly registered user
                    var emailBody = "Please Confirm your email address. <a href=\"#URL#\">Click here</a>";
                    //sample format of the callbackURL
                    //https://chuborekek:8080/Authentication/ConfirmEmail/userId=userId&code=confirmationCode
                    var callbackURL = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", "Authentication", new { userId = userToConfirm.Id, code = confirmationCode });
                    var emailBodyTemplate = emailBody.Replace("#URL#", callbackURL);
                    //------------SEND EMAIL WITH THE CONFIRMATION CODE AND CALLBACKURL
                    var emailresult = await _sendGridEmail.SendEmailAsync(userToConfirm.Email, "Email Confirmation", emailBodyTemplate);
                    if (emailresult)
                    {
                       // return true;
                       return Ok("Please verify your Email.Verification code is sent to your email.");
                    }
                   // return false;
                }
                //chuborekek is the real pikachu
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                {
                    "Email is already Confirmed"
                }
                });
                //return false;
            }
            
            return BadRequest(new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Email not Found"
                }
            });
            //return false;
        }

//----------------------------------------------------------Email Confirmation

        [Route("ConfirmEmail")]
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId,string code)
        {
            //check if null
            if(userId==null || code == null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid Confirmation Email Url"
                    }
                });
            }
            //check if user exist
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid Email parameters"
                    }
                });
            }

            //check confirmation code match for the user
            //var confirmationCode= Encoding.UTF8.GetString(Convert.FromBase64String(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            var status= result.Succeeded ? "Your email is Confirmed" : "Please contact Administrator, there is a problem confirming your Email";
            return Ok(status);
        }

//----------------------------------------------------------User Login 
        [Route("Login")]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody]UserLoginRequestDto userLoginRequestDto)
        {
            if(ModelState.IsValid)
            {  
                //check if user exists
                var existingUser= await _userManager.FindByEmailAsync(userLoginRequestDto.Email);
                if (existingUser == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                        "Invalid payload"
                        }
                    });
                }

                //check if email is confirmed
                if (!existingUser.EmailConfirmed)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                        "Email needs to be confirmed"
                        }
                    });
                }

                //check if Login is correct (username and password match)
                var password = userLoginRequestDto.Password;
                var isLoginCorrect = await _userManager.CheckPasswordAsync(existingUser,password);
                if (!isLoginCorrect)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                        "Invalid credentials"
                        }
                    });
                }

                //if Login is successful, generate the jwt token

                return Ok(await GenerateJwtToken(existingUser));


            }
            return BadRequest(new AuthResult()
            {
                Result = false,
                Errors= new List<string>()
                {
                    "Invalid payload"
                }
            });
        }

 //-----------------------------------------------------------Generating JWT Token for security purpose
        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
            //token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString()),

                }),

                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
                
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            //for refreshToken
            var refreshToken = new RefreshToken()
            {
                UserId = user.Id,
                Token = GenerateRandomString(23), //generate refresh Token
                JwtId= token.Id,
                IsUsed =false,
                IsRevoked=false,
                AddedDate= DateTime.UtcNow,
                ExpiryDate= DateTime.UtcNow.AddMonths(6)

            };
                await _context.RefreshTokens.AddAsync(refreshToken);
                await _context.SaveChangesAsync();
            return new AuthResult()
            {
                Result = true,
                Token = jwtToken,
                RefreshToken = refreshToken.Token
            };
          
        }
 
//----------------------------------------------------------generate JWT RefreshToken
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody]TokenRequestDto tokenRequestDto)
        {
            if (ModelState.IsValid)
            {
                var result = await VerifyAndGenerateToken(tokenRequestDto);

                if (result == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                         {
                            "Invalid Tokens"
                         }
                    });
                }

                return Ok(result);

            }
            return BadRequest(new AuthResult()
            {
                Result = false,
                Errors= new List<string>()
                {
                    "Invalid Parameters"
                }
            });
        }

//-----------------------------------------------------verify and generate new token for refresh token
        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequestDto tokenRequestDto)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                _tokenValidationParameters.ValidateLifetime = false;
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequestDto.Token,_tokenValidationParameters,out var validatedToken);

                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                        return null; 
                }
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x=>x.Type==JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);   
                if(expiryDate > DateTime.Now)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "expired token"
                        }
                    };
                }

                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequestDto.RefreshToken);
                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid token"
                        }
                    };
                }

                if(storedToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid token"
                        }
                    };
                }

                if (storedToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid token"
                        }
                    };
                }

                var jti = tokenInVerification.Claims.FirstOrDefault(x=>x.Type==JwtRegisteredClaimNames.Jti).Value;
                if(storedToken.JwtId!=jti)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid token"
                        }
                    };
                }

                if (storedToken.ExpiryDate < DateTime.UtcNow)
                    if (storedToken.JwtId != jti)
                    {
                        return new AuthResult()
                        {
                            Result = false,
                            Errors = new List<string>()
                        {
                            "Expired token"
                        }
                        };
                    }

                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser);



            }
            catch (Exception e)
            {

                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                        {
                            "Server Error"
                        }
                };
            }
        }

//-----------------------------------------------------convert Unix Time Stamp to DateTime
        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0,0,DateTimeKind.Utc);
            dateTimeVal= dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }

//------------------------------------------------------------------generate random string
        private string GenerateRandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

    }
}

//CHUBOREKEK :*