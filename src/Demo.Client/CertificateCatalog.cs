using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Demo.Contracts;

namespace Demo.Client
{
    internal static class CertificateCatalog
    {
        public static IList<X509Certificate2> LoadPersonal()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                return store.Certificates
                    .Cast<X509Certificate2>()
                    .Where(c => c.HasPrivateKey)
                    .OrderBy(c => c.Subject)
                    .ToList();
            }
        }

        public static X509Certificate2 FindAuth(IEnumerable<X509Certificate2> certs)
        {
            var list = certs.ToList();
            return list.FirstOrDefault(c => CertificateInspector.IsAuthenticationCertificate(c) && IsEsteid(c))
                ?? list.FirstOrDefault(c => CertificateInspector.IsAuthenticationCertificate(c) && IsLab(c))
                ?? list.FirstOrDefault(CertificateInspector.IsAuthenticationCertificate);
        }

        public static X509Certificate2 FindSign(IEnumerable<X509Certificate2> certs)
        {
            var list = certs.ToList();
            return list.FirstOrDefault(c => CertificateInspector.IsSigningCertificate(c) && IsEsteid(c))
                ?? list.FirstOrDefault(c => CertificateInspector.IsSigningCertificate(c) && IsLab(c))
                ?? list.FirstOrDefault(CertificateInspector.IsSigningCertificate);
        }

        public static bool IsLab(X509Certificate2 cert)
        {
            return (cert.Issuer ?? string.Empty).IndexOf("IIS-ID Home Lab", StringComparison.OrdinalIgnoreCase) >= 0
                || (cert.Subject ?? string.Empty).IndexOf("IIS-ID Home Lab", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsEsteid(X509Certificate2 cert)
        {
            if (cert == null || IsLab(cert))
                return false;

            var issuer = cert.Issuer ?? string.Empty;
            return issuer.IndexOf("ESTEID", StringComparison.OrdinalIgnoreCase) >= 0
                || issuer.IndexOf("EE-GovCA", StringComparison.OrdinalIgnoreCase) >= 0
                || issuer.IndexOf("EEGovCA", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static string Describe(X509Certificate2 cert)
        {
            if (cert == null)
                return "(puudub)";

            var kind = CertificateInspector.IsSigningCertificate(cert) && !CertificateInspector.IsAuthenticationCertificate(cert)
                ? "PIN2"
                : CertificateInspector.IsAuthenticationCertificate(cert) ? "PIN1" : "sert";

            var source = IsEsteid(cert) ? "ID-kaart" : IsLab(cert) ? "lab" : "muu";
            var cn = GetCn(cert.Subject) ?? cert.Subject;
            return source + " / " + kind + " — " + cn;
        }

        private static string GetCn(string subject)
        {
            if (string.IsNullOrEmpty(subject))
                return null;
            var marker = "CN=";
            var start = subject.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
                return null;
            start += marker.Length;
            var end = subject.IndexOf(',', start);
            return end < 0 ? subject.Substring(start) : subject.Substring(start, end - start);
        }
    }
}
