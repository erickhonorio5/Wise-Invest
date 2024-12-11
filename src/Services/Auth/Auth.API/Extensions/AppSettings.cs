namespace Auth.API.Extensions;

public class AppSettings
{
    public string Secret { get; set; }
    public int ExpirationDate{ get; set; }
    public string Issuer { get; set; }
    public string ValidIn { get; set; }

}
