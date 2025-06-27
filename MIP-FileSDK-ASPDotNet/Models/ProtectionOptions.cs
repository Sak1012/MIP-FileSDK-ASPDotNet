using Microsoft.AspNetCore.Mvc;

namespace MIP_FileSDK_ASPDotNet.Models
{
    public class ProtectionOptions
    {
        public List<string> Emails { get; set; } = new();
        public string Rights { get; set; } = "View";
    }
}
