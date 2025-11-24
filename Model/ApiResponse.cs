namespace StudentMS.Model
{
    public class ApiResponse
    {
        public bool status { get; set; }
        public bool Status { get; internal set; }
        public string message { get; set; } = string.Empty;
        public string Messages { get; internal set; }
    }
}
