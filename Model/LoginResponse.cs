namespace StudentMs.Model
{
    public class LoginResponse
    {
            public int Year { get; set; }
            public string StudentMail { get; set; } = string.Empty;
            public string StudentName { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
            public string CollegeName { get; set; } = string.Empty;
            public string StudentRollNo { get; set; } = string.Empty;
            public string Department { get; set; } = string.Empty;
            public long StudentPhoneNo { get; set; }
            public string Degree { get; set; } = string.Empty;
    }
}
