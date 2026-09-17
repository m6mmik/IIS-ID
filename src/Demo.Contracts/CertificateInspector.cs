using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Demo.Contracts
{
    public static class CertificateInspector
    {
        public static IReadOnlyList<string> GetPolicyOids(X509Certificate2 cert)
        {
            var oids = new List<string>();
            foreach (var extension in cert.Extensions)
            {
                if (extension.Oid == null || extension.Oid.Value != "2.5.29.32")
                    continue;

                var formatted = extension.Format(true) ?? string.Empty;
                foreach (Match match in Regex.Matches(formatted, @"\d+(\.\d+)+"))
                    oids.Add(match.Value);
            }

            return oids.Distinct().ToList();
        }

        public static bool HasEku(X509Certificate2 cert, string oid)
        {
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            return eku != null && eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Any(o => o.Value == oid);
        }

        public static bool HasKeyUsage(X509Certificate2 cert, X509KeyUsageFlags flag)
        {
            var ku = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            return ku != null && ku.KeyUsages.HasFlag(flag);
        }

        public static bool IsAuthenticationCertificate(X509Certificate2 cert)
        {
            return HasEku(cert, EsteidPolicies.ClientAuthEku);
        }

        public static bool IsSigningCertificate(X509Certificate2 cert)
        {
            return HasKeyUsage(cert, X509KeyUsageFlags.NonRepudiation);
        }

        public static string GetPersonalCode(X509Certificate2 cert)
        {
            var match = Regex.Match(cert.Subject, @"SERIALNUMBER=(PNOEE-)?(?<id>\d{11})", RegexOptions.IgnoreCase);
            if (match.Success)
                return match.Groups["id"].Value;

            match = Regex.Match(cert.Subject, @"OID\.2\.5\.4\.5=(PNOEE-)?(?<id>\d{11})", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups["id"].Value : null;
        }

        public static PolicyCheckResult CheckAuthenticationPolicy(X509Certificate2 cert, bool allowLabCertificates)
        {
            var policies = GetPolicyOids(cert);
            if (policies.Contains(EsteidPolicies.AnyPolicy) && policies.Count == 1)
                return PolicyCheckResult.Reject("anyPolicy (2.5.29.32.0) ei ole ID-kaardi poliitika tõend.");

            if (allowLabCertificates && cert.Issuer.IndexOf("IIS-ID Home Lab", StringComparison.OrdinalIgnoreCase) >= 0)
                return PolicyCheckResult.Accept("Lab-sertifikaat (kodune test-CA).");

            if (!policies.Contains(EsteidPolicies.NcpPlus))
                return PolicyCheckResult.Reject("Puudub NCP+ OID 0.4.0.2042.1.2.");

            var issuer = cert.Issuer ?? string.Empty;
            if (issuer.IndexOf("ESTEID2018", StringComparison.OrdinalIgnoreCase) >= 0 &&
                policies.Any(p => EsteidPolicies.Esteid2018Documents.Contains(p)))
                return PolicyCheckResult.Accept("ESTEID2018 + NCP+ + dokumendipoliitika.");

            if (issuer.IndexOf("ESTEID2025", StringComparison.OrdinalIgnoreCase) >= 0 &&
                policies.Any(p => EsteidPolicies.Esteid2025Documents.Contains(p)))
                return PolicyCheckResult.Accept("ESTEID2025 + NCP+ + dokumendipoliitika.");

            return PolicyCheckResult.Reject("NCP+ on olemas, aga dokumendipoliitika OID ei klapi väljastajaga.");
        }
    }

    public sealed class PolicyCheckResult
    {
        public bool Accepted { get; private set; }
        public string Reason { get; private set; }

        public static PolicyCheckResult Accept(string reason) => new PolicyCheckResult { Accepted = true, Reason = reason };
        public static PolicyCheckResult Reject(string reason) => new PolicyCheckResult { Accepted = false, Reason = reason };
    }
}
