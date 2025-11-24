namespace StudentMS.Model
{
    public class StudentRequest
    {
        public string? studentName { get; set; }
        public string ? studentEmail { get; set; }
        public string ?PasswordHash { get; set; }
        public string ?CollegeName { get; set; }
        public string? StudentRollNo { get; set; }
        public string? Department { get; set; }
        public int? Year { get; set; } = 0;
        public string? Degree { get; set; }
    }
}
