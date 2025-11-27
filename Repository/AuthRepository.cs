using Dapper;
using Microsoft.IdentityModel.Tokens;
using MySqlConnector;
using StudentMs.Model;
using StudentMs.Repository.IRepository;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StudentMs.Repository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly IDbConnection _dbConnection;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _context;
        private readonly HttpClient _httpClient = new HttpClient();


        public AuthRepository(IConfiguration configuration, IHttpContextAccessor context)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            var connectionString = _configuration.GetConnectionString("DefaultConnection") ?? throw new ArgumentNullException(nameof(configuration));
            if (string.IsNullOrEmpty(connectionString))
            {
                throw new ArgumentNullException("Connection string 'DefaultConnection' not found.");
            }
            using var _ = _dbConnection = new MySqlConnector.MySqlConnection(connectionString);
        }

        public async Task<LoginResult> LoginStudentAsync(string studentMail, string password)
        {
            var userid = await GetUserId(studentMail);
            if (userid == 0)
            {
                return new LoginResult
                {
                    Messages = new List<string> { "Invalid email or password" }
                };
            }
            var studentmobile = await GetMobileNo(studentMail);

            // Get hashed password from DB
            var storedHash = await GetPwd(studentMail);

            // ❗Verify password with BCrypt
            bool isPasswordCorrect = BCrypt.Net.BCrypt.Verify(password, storedHash);

            if (!isPasswordCorrect)
            {
                return new LoginResult
                {
                    Messages = new List<string> { "Invalid email or password" }
                };
            }
            var user = new User
            {
                StudentId = userid,
                StudentMail = studentMail,
                StudentPhoneNo = studentmobile != null ? long.Parse(studentmobile) : 0
            };
            var userIP = GetClientIpAddress();
            var loginResult = new LoginResult();
            bool isKnowIp = await IsIpValid(userid, userIP);
            if (isKnowIp)
            {
                await SaveLoginLog(userid, userIP, "Login Successful");
                loginResult.User = user;
                return loginResult;
            }
            else
            {
                loginResult.Messages.Add("OTP Sent via SMS");
                await SaveLoginLog(userid, userIP, "OTP Sent (New IP)");
                await GenerateAndSendOTP(userid, studentmobile!);
                loginResult.User = user;
                return loginResult;
            }
        }



        private async Task<string> GenerateAndSendOTP(int userId, string studentMobile)
        {
            var UserName = await GetUserName(userId);
            if (string.IsNullOrWhiteSpace(studentMobile))
                throw new ArgumentNullException(nameof(studentMobile), $"Mobile number is required to send OTP for {UserName}.");

            // Use a private method to manage OTP storage internally
            string otp = SaveOTP(userId);

            // Fast2SMS configuration
            var apiKey = _configuration["SMSSettings:Fast2SMSApiKey"];
            var senderId = _configuration["SMSSettings:SenderId"] ?? "TXTIND";
            var route = _configuration["SMSSettings:Route"] ?? "v3";

            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException("Fast2SMS API key is missing.");

            // Compose message
            var message = $@"
<div style='font-family: Arial, sans-serif; max-width: 500px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;'>
    <h2 style='color:#333;'>🔒 Your OTP Code</h2>
    <p>👋 Dear <strong>{UserName}</strong>,</p>
    <p>🔢 Your OTP is:</p>
    <p style='font-size: 20px; font-weight: bold; color: #fff; background-color: #007bff; padding: 10px 15px; display: inline-block; border-radius: 5px;'>{otp}</p>
    <p>⏰ It is valid for 24 hours. Do not share it with anyone. ❗</p>
    <p style='font-size: 12px; color: #999;'>📩 This is an automated message. Please do not reply.</p>
</div>";

            // Send SMS
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://www.fast2sms.com/dev/bulkV2")
            {
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("authorization", apiKey),
                    new KeyValuePair<string, string>("sender_id", senderId),
                    new KeyValuePair<string, string>("message", message),
                    new KeyValuePair<string, string>("route", route),
                    new KeyValuePair<string, string>("numbers", studentMobile)
                })
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            try
            {
                using var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<JsonElement>(content);

                Console.WriteLine($"OTP {otp} sent to {studentMobile} for userId {userId}. Response: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to send OTP to userId {userId}: {ex.Message}");
                throw new InvalidOperationException("Failed to send OTP via SMS.", ex);
            }

            return otp;
        }

        public async Task<string?> GetUserName(int userId)
        {
            var connection = new MySqlConnector.MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            var storedProcedure = "GetStudentNameById";
            var parameters = new DynamicParameters();
            parameters.Add("p_StudentId", userId, DbType.Int32);
            connection.Open();
            var result = await connection.QueryFirstOrDefaultAsync<string>(
                storedProcedure,
                parameters,
                commandType: CommandType.StoredProcedure
            );
            return result;
        }

        private string SaveOTP(int userId)
        {
            if (userId <= 0)
                throw new ArgumentOutOfRangeException(nameof(userId), "UserId must be a positive integer.");
            // Generate a 6-digit OTP
            var random = new Random();
            var otp = random.Next(100000, 999999).ToString();
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            using var con = new MySqlConnector.MySqlConnection(connectionString);
            con.Open();
            var sp = "SaveUserOTP";
            var parameters = new DynamicParameters();
            parameters.Add("p_UserId", userId, DbType.Int32);
            parameters.Add("p_OTP", otp, DbType.String);
            parameters.Add("p_ExpiryTime", DateTime.UtcNow.AddHours(24), DbType.DateTime);
            var result = con.Execute(sp, parameters, commandType: CommandType.StoredProcedure);
            return otp;
        }

        public async Task<string?> GetMobileNo(string studentMail)
        {
            var connection = new MySqlConnector.MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            var storedProcedure = "GetStudentMobileByEmail";
            var parameters = new DynamicParameters();
            parameters.Add("p_StudentMail", studentMail, DbType.String);
            connection.Open();
            var result = await connection.QueryFirstOrDefaultAsync<string>(
                storedProcedure,
                parameters,
                commandType: CommandType.StoredProcedure
            );
            return result;
        }

        private async Task<bool> IsIpValid(int userid, object userIP)
        {

            var connection = new MySqlConnector.MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            var storedProcedure = "IsIpKnown";
            var parameters = new DynamicParameters();
            parameters.Add("p_UserId", userid, DbType.Int32);
            parameters.Add("p_IPAddress", userIP.ToString(), DbType.String);
            connection.Open();
            var result = await connection.QueryFirstOrDefaultAsync<int>(
                storedProcedure,
                parameters,
                commandType: CommandType.StoredProcedure
            );
            return result > 0;
        }



        public async Task<int> SaveLoginLog(int userid, object userIP, string status)
        {
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            using var con = new MySqlConnector.MySqlConnection(connectionString);
            var sp = "SaveLoginLog";
            var parameters = new DynamicParameters();
            parameters.Add("p_UserId", userid, DbType.Int32);
            parameters.Add("p_IPAddress", userIP.ToString(), DbType.String);
            parameters.Add("p_Status", status, DbType.String);
            var result = await con.ExecuteAsync(sp, parameters, commandType: CommandType.StoredProcedure);

            return result;
        }


        private object GetClientIpAddress()
        {
            var httpContext = _context.HttpContext;
            if (httpContext == null)
            {
                return "Unknown";
            }
            string ip = httpContext.Request.Headers["X-Forwarded-For"]!;
            if (string.IsNullOrEmpty(ip))
            {
                ip = httpContext.Connection.RemoteIpAddress?.ToString()!;
            }
            else
            {
                ip = ip.Split(',')[0];
            }
            if (ip == "::1")
            {
                ip = ip = GetLocalIPv4();
            }
            return ip!;
        }
        private string GetLocalIPv4()
        {
            string localIP = "127.0.0.1";
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    localIP = ip.ToString();
                    break;
                }
            }
            return localIP;
        }

        public async Task<string> GetPwd(string studentMail)
        {
            using var con = new MySqlConnector.MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            var sp = "GetStudentPwdByEmail";
            var parameters = new DynamicParameters();
            parameters.Add("p_StudentMail", studentMail, DbType.String);
            var pwd = await con.QueryFirstOrDefaultAsync<string>(sp, parameters, commandType: CommandType.StoredProcedure);
            return pwd ?? string.Empty;
        }

        public async Task<int> GetUserId(string studentMail)
        {
            using var con = new MySqlConnector.MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            var sp = "GetStudentIdByEmail";
            var parameters = new DynamicParameters();
            parameters.Add("p_StudentMail", studentMail, DbType.String);
            var userId = await con.QueryFirstOrDefaultAsync<int>(sp, parameters, commandType: CommandType.StoredProcedure);
            return userId;
        }
        public LoginResponse GenerateJwtToken(User user)
        {

            if (user == null)
                throw new ArgumentNullException(nameof(user), "User object cannot be null when generating JWT token.");

            var jwtSettings = _configuration.GetSection("Jwt");
            var keyString = jwtSettings["Key"];
            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];
            var expiresInMinutesStr = jwtSettings["ExpiresInMinutes"];
            if (string.IsNullOrWhiteSpace(keyString) || string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(audience) || string.IsNullOrWhiteSpace(expiresInMinutesStr))
            {
                throw new InvalidOperationException("Missing required JWT configuration (Key, Issuer, Audience, or ExpiresInMinutes).");
            }
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            int expiresInMinutes = int.TryParse(expiresInMinutesStr, out int minutes) ? minutes : 60;

            // Fix CS1061: Use correct property names from User class
            // If User class does not have these properties, you must add them to the User class.
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.StudentMail ?? ""), // Ensure User has StudentMail property
                new Claim("StudentName", user.StudentName ?? ""),
                new Claim("UserId", user.StudentId.ToString()),
                new Claim("Role", "Student"),
                new Claim("Department", user.Department ?? ""),
                new Claim("CollegeName", user.CollegeName ?? ""),
                new Claim("Degree", user.Degree ?? ""),
                new Claim("Year", user.Year.ToString()),
                new Claim("StudentRollNo", user.StudentRollNo ?? ""),
                new Claim("StudentPhoneNo", user.StudentPhoneNo.ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64)
            };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiresInMinutes),
                signingCredentials: creds);


            return new LoginResponse
            {
                CollegeName = user.CollegeName ?? "",
                Department = user.Department ?? "",
                Degree = user.Degree ?? "",
                Password = user.Password ?? "",
                StudentMail = user.StudentMail ?? "",
                StudentName = user.StudentName ?? "",
                StudentPhoneNo = user.StudentPhoneNo,
                StudentRollNo = user.StudentRollNo ?? "",
                Year = user.Year,
            };
        }
        public async Task<int> CheckOTP(int StudentId, int otp)
        {
            var connection = new MySqlConnector.MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            var storedProcedure = "CheckUserOTP";
            var parameters = new DynamicParameters();
            parameters.Add("p_StudentId", StudentId, DbType.Int32);
            parameters.Add("p_OTP", otp, DbType.Int32);
            connection.Open();
            var result = await connection.QueryFirstOrDefaultAsync<int>(
                storedProcedure,
                parameters,
                commandType: CommandType.StoredProcedure
            );
            return result;
        }
        public async Task<int> ChangePWD(int studentId, string OldPwd, string newPwd)
        {
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            using var con = new MySqlConnector.MySqlConnection(connectionString);
            var sp = "ChangeStudentPassword";
            var parameters = new DynamicParameters();
            var hashedNewPassword = BCrypt.Net.BCrypt.HashPassword(newPwd);
            var hashedOldPassword = BCrypt.Net.BCrypt.HashPassword(OldPwd);
            parameters.Add("p_StudentId", studentId, DbType.Int32);
            parameters.Add("p_OldPwd", hashedOldPassword, DbType.String);
            parameters.Add("p_NewPwd", hashedNewPassword, DbType.String);
            var result = await con.ExecuteAsync(sp, parameters, commandType: CommandType.StoredProcedure);
            return result;
        }
        public async Task<string> ForgotPWD(string studentMail)
        {
            var userid = await GetUserId(studentMail);
            if (userid == 0)
            {
                throw new InvalidOperationException("Invalid email address provided.");
            }
            var tempPWD = Guid.NewGuid().ToString().Substring(0, 8);
            var hashedNewPassword = BCrypt.Net.BCrypt.HashPassword(tempPWD);
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            using var con = new MySqlConnector.MySqlConnection(connectionString);
            var sp = "ResetStudentPassword";
            var parameters = new DynamicParameters();
            parameters.Add("p_StudentId", userid, DbType.Int32);
            parameters.Add("p_NewPwd", hashedNewPassword, DbType.String);
            var result = await con.ExecuteAsync(sp, parameters, commandType: CommandType.StoredProcedure);
            if (result > 0)
            {
                var msg = $"Hello Student,\n\nYour temporary password is: {tempPWD}\n\nPlease login and change it.";


                await SendEmailAsync(studentMail, "Your Temporary Password", msg);

                return "Temporary password sent to your email.";
            }
            else
            {
                throw new InvalidOperationException("Failed to reset password.");
            }
        }

        public async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                var smtpHost = _configuration["EmailSettings:SmtpHost"];
                var smtpPort = int.Parse(_configuration["EmailSettings:SmtpPort"] ?? "587");
                var smtpUser = _configuration["EmailSettings:SmtpUser"];
                var smtpPass = _configuration["EmailSettings:SmtpPass"];
                var fromEmail = _configuration["EmailSettings:FromEmail"];
                using var client = new SmtpClient(smtpHost, smtpPort)
                {
                    Credentials = new NetworkCredential(smtpUser, smtpPass),
                    EnableSsl = true
                };
                var mailMessage = new MailMessage
                {
                    From = new MailAddress(address: fromEmail),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(toEmail);
                await client.SendMailAsync(mailMessage);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to send email to {toEmail}: {ex.Message}");
                return false;
            }
        }



    }
}