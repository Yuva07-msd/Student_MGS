
using StudentMs.Model;

namespace StudentMs.Repository.IRepository
{
    public interface IAuthRepository
    {
        public Task<LoginResult> LoginStudentAsync(string studentMail, string password);
        LoginResponse GenerateJwtToken(User user);
        Task<int> SaveLoginLog(int userid, object userIP, string status);
        Task<string?> GetUserName(int userId);
        Task<string?> GetMobileNo(string studentMail);
        Task<string> GetPwd(string studentMail);
        Task<int> GetUserId(string studentMail);
        Task<int> CheckOTP(int studentId, int otp);
        Task<int>ChangePWD(int studentId,string OldPwd, string newPwd);
        Task<string> ForgotPWD(string studentMail);
        Task<bool> SendEmailAsync(string toEmail, string subject, string body);
    }
}
