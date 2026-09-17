using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Demo.Client
{
    internal static class LocalSigner
    {
        public static SignedPayload Sign(X509Certificate2 signingCert, string text)
        {
            if (signingCert == null)
                throw new InvalidOperationException("Allkirjastamise sertifikaat (PIN2) puudub.");

            var data = Encoding.UTF8.GetBytes(text ?? string.Empty);
            using (var ecdsa = signingCert.GetECDsaPrivateKey())
            {
                if (ecdsa != null)
                {
                    var hash = ecdsa.KeySize <= 256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
                    return new SignedPayload
                    {
                        Signature = ecdsa.SignData(data, hash),
                        HashAlgorithm = hash.Name,
                        CertificateDer = signingCert.Export(X509ContentType.Cert)
                    };
                }
            }

            using (var rsa = signingCert.GetRSAPrivateKey())
            {
                if (rsa == null)
                    throw new InvalidOperationException("Sertifikaadil pole RSA ega ECDSA privaatvõtit.");

                return new SignedPayload
                {
                    Signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                    HashAlgorithm = HashAlgorithmName.SHA256.Name,
                    CertificateDer = signingCert.Export(X509ContentType.Cert)
                };
            }
        }
    }

    internal sealed class SignedPayload
    {
        public byte[] Signature { get; set; }
        public string HashAlgorithm { get; set; }
        public byte[] CertificateDer { get; set; }
    }
}
