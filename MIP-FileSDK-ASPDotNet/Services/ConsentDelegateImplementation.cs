using Microsoft.InformationProtection;

namespace MIP_FileSDK_ASPDotNet.Services
{
    public class ConsentDelegateImplementation : IConsentDelegate
    {
        public Consent GetUserConsent(string url)
        {
            return Consent.Accept;
        }
    }
}