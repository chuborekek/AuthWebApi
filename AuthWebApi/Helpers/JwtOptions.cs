namespace AuthWebApi.Helpers
{
    public class JwtOptions
    {
        public string Secret { get; set; }
        public TimeSpan ExpiryTimeFrame { get;set; }
    }
}
