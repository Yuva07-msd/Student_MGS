using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using StudentMs.Model;
using StudentMs.Repository.IRepository;

namespace StudentMs.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AAuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;

        public AAuthController(IAuthRepository authRepository)
        {
            _authRepository = authRepository;
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.StudentMail))
            {
                return BadRequest("StudentMail is required.");
            }
            if (string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Password is required.");
            }

            var loginresult = await _authRepository.LoginStudentAsync(request.StudentMail, request.Password);
            if (loginresult == null || loginresult.User == null)
            {
                return Unauthorized("Invalid credentials.");
            }
            var tokenResponse = _authRepository.GenerateJwtToken(loginresult.User);
            return Ok(new
            {
                UserDetails = tokenResponse,
                Messages = loginresult.Messages
            });
        }
        [HttpPost("check-otp")]
        public async Task<IActionResult> CheckOTP([FromBody] CheckOTP request)
        {
            if (request.StudentId <= 0)
            {
                return BadRequest("Invalid StudentId.");
            }
            if (request.OTP <= 0)
            {
                return BadRequest("Invalid OTP.");
            }
            var isValidOtp = await _authRepository.CheckOTP(request.StudentId, request.OTP);
            if (isValidOtp > 0)
            {
                return Ok(new { Message = "OTP is valid." });
            }
            else
            {
                return Unauthorized("Invalid OTP.");
            }
        }
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (request.StudentId <= 0)
            {
                return BadRequest("Invalid StudentId.");
            }
            if (string.IsNullOrEmpty(request.OldPwd))
            {
                return BadRequest("Old password is required.");
            }
            if (string.IsNullOrEmpty(request.NewPwd))
            {
                return BadRequest("New password is required.");
            }
            var response = await _authRepository.ChangePWD(request.StudentId, request.OldPwd, request.NewPwd);
            var result = response switch
            {
                1 => Ok(new { Message = "Password changed successfully." }),
                2 => BadRequest("Old password is incorrect."),
                _ => StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while changing the password.")
            };
            return result;

        }
    }
}
