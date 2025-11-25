namespace StudentMs.Model
{
    public class User
    {
        public int StudentId { get; set; }
        public string? StudentMail { get; set; }
        public string? StudentName { get; set; }
        public string? Department { get; set; }
        public string? CollegeName { get; set; }
        public string? Degree { get; set; }
        public int Year { get; set; }
        public string? StudentRollNo { get; set; }
        public long StudentPhoneNo { get; set; }
        public string? Password { get; set; }
    }
}