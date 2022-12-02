namespace AuthWebApi.Interfaces
{
    public interface ISendGridEmail
    {
        Task<bool> SendEmailAsync(string toEmail, string subject, string message);
    }
}
