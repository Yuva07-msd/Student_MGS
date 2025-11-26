namespace StudentMs.Model
{
    public class LoginRequest
    {
        public string StudentMail { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
    public class LoginResult
    {
        public User? User { get; set; }
        public List<string> Messages { get; set; } = new List<string>();
    }
    public class CheckOTP
    {
        public int StudentId { get; set; }
        public int OTP { get; set; }
    }
    public class ChangePasswordRequest
    {
        public int StudentId { get; set; }
        public string OldPwd { get; set; } = string.Empty;
        public string NewPwd { get; set; } = string.Empty;

    }
}
