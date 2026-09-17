using System;
using System.Configuration;
using System.Diagnostics;
using System.IdentityModel.Claims;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.Text;
using System.Web;
using System.Web.Hosting;
using Demo.Contracts;

namespace Demo.Service
{
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    public class DemoService : IDemoService
    {
        public WhoAmIResponse WhoAmI(WhoAmIRequest request)
        {
            var cert = GetClientCertificate();
            if (cert == null)
            {
                ServiceLog.Call("WhoAmI", request?.CorrelationId, null,
                    "FAULT kliendisertifikaat puudub (IIS ei kusinud seda voi ei edastanud rakendusele)");
                throw new FaultException("Kliendisertifikaat puudub. IIS peab TLS kätluse ajal sertifikaati küsima.");
            }

            var allowLab = AllowLabCertificates();
            var policy = CertificateInspector.CheckAuthenticationPolicy(cert, allowLab);
            ServiceLog.Call("WhoAmI", request?.CorrelationId, cert,
                (policy.Accepted ? "OK poliitika: " : "POLIITIKA TAGASI LUKATUD: ") + policy.Reason);

            return new WhoAmIResponse
            {
                CorrelationId = request?.CorrelationId,
                BackendName = GetBackendName(),
                AppPool = GetAppPool(),
                ProcessId = Process.GetCurrentProcess().Id,
                AuthCertSubject = cert.Subject,
                AuthCertIssuer = cert.Issuer,
                AuthCertSerial = cert.SerialNumber,
                PersonalCode = CertificateInspector.GetPersonalCode(cert),
                CertificatePolicies = CertificateInspector.GetPolicyOids(cert).ToArray(),
                PolicyAccepted = policy.Accepted,
                PolicyReason = policy.Reason,
                ServerTimeUtc = DateTime.UtcNow.ToString("o")
            };
        }

        public PingResponse Ping(PingRequest request)
        {
            var cert = GetClientCertificate();
            if (cert == null)
            {
                ServiceLog.Call("Ping", request?.CorrelationId, null, "FAULT kliendisertifikaat puudub");
                throw new FaultException("Kliendisertifikaat puudub. Logi esmalt sisse (PIN1).");
            }

            ServiceLog.Call("Ping", request?.CorrelationId, cert, "OK");

            return new PingResponse
            {
                CorrelationId = request?.CorrelationId,
                Echo = string.IsNullOrEmpty(request?.Message) ? "pong" : request.Message,
                BackendName = GetBackendName(),
                AppPool = GetAppPool(),
                ProcessId = Process.GetCurrentProcess().Id,
                PersonalCode = CertificateInspector.GetPersonalCode(cert),
                ServerTimeUtc = DateTime.UtcNow.ToString("o")
            };
        }

        public SignVerifyResponse SubmitSignature(SignRequest request)
        {
            var authCert = GetClientCertificate();
            if (authCert == null)
            {
                ServiceLog.Call("SubmitSignature", request?.CorrelationId, null, "FAULT kliendisertifikaat puudub");
                throw new FaultException("Kliendisertifikaat puudub (PIN1 / mTLS).");
            }
            if (request == null || request.SigningCertificateDer == null || request.Signature == null)
                throw new FaultException("Allkirja päring on tühi.");

            var signingCert = new X509Certificate2(request.SigningCertificateDer);
            var data = Encoding.UTF8.GetBytes(request.DataUtf8 ?? string.Empty);
            var valid = VerifySignature(signingCert, data, request.Signature, request.HashAlgorithm);

            var authId = CertificateInspector.GetPersonalCode(authCert);
            var signId = CertificateInspector.GetPersonalCode(signingCert);
            var samePerson = !string.IsNullOrEmpty(authId) && authId == signId;

            string message;
            if (!valid)
                message = "Allkiri ei klapi allkirjastamise sertifikaadiga.";
            else if (!samePerson)
                message = "Allkiri on matemaatiliselt korrektne, aga isikukood ei kattu PIN1 autentimissertifikaadiga.";
            else
                message = "PIN2 allkiri on korrektne ja kuulub samale isikule, kes autenditi PIN1-ga.";

            ServiceLog.Call("SubmitSignature", request.CorrelationId, authCert,
                "allkiri=" + valid + " samaIsik=" + samePerson);

            return new SignVerifyResponse
            {
                CorrelationId = request.CorrelationId,
                BackendName = GetBackendName(),
                ProcessId = Process.GetCurrentProcess().Id,
                SignatureValid = valid,
                SamePersonAsAuthCert = samePerson,
                SigningCertSubject = signingCert.Subject,
                AuthPersonalCode = authId,
                SignPersonalCode = signId,
                Message = message
            };
        }

        private static bool VerifySignature(X509Certificate2 cert, byte[] data, byte[] signature, string hashName)
        {
            var hash = ParseHash(hashName, cert);
            try
            {
                using (var ecdsa = cert.GetECDsaPublicKey())
                {
                    if (ecdsa != null)
                        return ecdsa.VerifyData(data, signature, hash);
                }

                using (var rsa = cert.GetRSAPublicKey())
                {
                    if (rsa != null)
                        return rsa.VerifyData(data, signature, hash, RSASignaturePadding.Pkcs1);
                }
            }
            catch (CryptographicException)
            {
                return false;
            }

            return false;
        }

        private static HashAlgorithmName ParseHash(string hashName, X509Certificate2 cert)
        {
            if (!string.IsNullOrEmpty(hashName))
                return new HashAlgorithmName(hashName);

            using (var ecdsa = cert.GetECDsaPublicKey())
            {
                if (ecdsa != null)
                    return ecdsa.KeySize <= 256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
            }

            return HashAlgorithmName.SHA256;
        }

        internal static X509Certificate2 GetClientCertificate()
        {
            var httpCert = HttpContext.Current?.Request.ClientCertificate;
            if (httpCert != null && httpCert.IsPresent && httpCert.Certificate != null && httpCert.Certificate.Length > 0)
                return new X509Certificate2(httpCert.Certificate);

            var context = ServiceSecurityContext.Current;
            if (context?.AuthorizationContext?.ClaimSets == null)
                return null;

            foreach (var set in context.AuthorizationContext.ClaimSets.OfType<X509CertificateClaimSet>())
                return set.X509Certificate;

            return null;
        }

        internal static string GetBackendName()
        {
            var site = HostingEnvironment.SiteName;
            if (string.IsNullOrEmpty(site))
                site = Environment.GetEnvironmentVariable("DEMO_BACKEND");
            if (string.IsNullOrEmpty(site))
                site = "IIS";
            return Environment.MachineName + "/" + site;
        }

        internal static string GetAppPool()
        {
            return Environment.GetEnvironmentVariable("APP_POOL_ID")
                ?? HttpRuntime.AppDomainAppId
                ?? GetBackendName();
        }

        internal static bool AllowLabCertificates()
        {
            var value = ConfigurationManager.AppSettings["AllowLabCertificates"];
            return string.IsNullOrEmpty(value) || !string.Equals(value, "false", StringComparison.OrdinalIgnoreCase);
        }
    }
}
