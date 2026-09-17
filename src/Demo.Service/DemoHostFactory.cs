using System;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Security;

namespace Demo.Service
{
    public class DemoHostFactory : ServiceHostFactory
    {
        protected override ServiceHost CreateServiceHost(Type serviceType, Uri[] baseAddresses)
        {
            var host = base.CreateServiceHost(serviceType, baseAddresses);
            var auth = host.Credentials.ClientCertificate.Authentication;
            auth.CertificateValidationMode = X509CertificateValidationMode.PeerOrChainTrust;
            auth.RevocationMode = ReadRevocationMode();
            return host;
        }

        private static System.Security.Cryptography.X509Certificates.X509RevocationMode ReadRevocationMode()
        {
            var value = Environment.GetEnvironmentVariable("DEMO_REVOCATION")
                        ?? System.Configuration.ConfigurationManager.AppSettings["RevocationMode"]
                        ?? "NoCheck";

            if (string.Equals(value, "Online", StringComparison.OrdinalIgnoreCase))
                return System.Security.Cryptography.X509Certificates.X509RevocationMode.Online;
            if (string.Equals(value, "Offline", StringComparison.OrdinalIgnoreCase))
                return System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline;

            return System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        }
    }
}
