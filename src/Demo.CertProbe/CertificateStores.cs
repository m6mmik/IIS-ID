using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Demo.CertProbe
{
    /// <summary>
    /// Hoidlate otsing. HTTP.sys ja Schannel kasutavad LocalMachine hoidlaid,
    /// seetõttu on oluline näidata, KUS iga ahela lüli päriselt asub.
    /// </summary>
    internal static class CertificateStores
    {
        private static readonly string[] Names = { "Root", "CA", "ClientAuthIssuer", "My", "TrustedPeople" };

        private static readonly StoreLocation[] Locations =
        {
            StoreLocation.LocalMachine,
            StoreLocation.CurrentUser
        };

        public static IReadOnlyList<string> Locate(X509Certificate2 cert)
        {
            var found = new List<string>();
            if (cert == null)
                return found;

            foreach (var location in Locations)
            {
                foreach (var name in Names)
                {
                    if (Contains(location, name, cert.Thumbprint))
                        found.Add(location + "\\" + name);
                }
            }

            return found;
        }

        public static bool Contains(StoreLocation location, string storeName, string thumbprint)
        {
            return Read(location, storeName, certs =>
                certs.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0);
        }

        public static X509Certificate2 FindBySubject(StoreLocation location, string storeName, string subject)
        {
            return Read(location, storeName, certs =>
            {
                foreach (var cert in certs)
                {
                    if (string.Equals(cert.Subject, subject, StringComparison.OrdinalIgnoreCase))
                        return cert;
                }
                return null;
            });
        }

        public static int Count(StoreLocation location, string storeName)
        {
            return Read(location, storeName, certs => certs.Count);
        }

        public static int CountMatching(StoreLocation location, string storeName, params string[] fragments)
        {
            return Read(location, storeName, certs =>
            {
                var hits = 0;
                foreach (var cert in certs)
                {
                    foreach (var fragment in fragments)
                    {
                        if (cert.Subject != null &&
                            cert.Subject.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            hits++;
                            break;
                        }
                    }
                }
                return hits;
            });
        }

        public static X509Certificate2 FindServerCertificate(string reference)
        {
            foreach (var location in Locations)
            {
                var cert = Read(location, "My", certs =>
                {
                    X509Certificate2 match = null;
                    foreach (var candidate in certs)
                    {
                        if (!candidate.HasPrivateKey)
                            continue;
                        var byThumb = string.Equals(candidate.Thumbprint, reference, StringComparison.OrdinalIgnoreCase);
                        var bySubject = candidate.Subject != null &&
                                        candidate.Subject.IndexOf(reference, StringComparison.OrdinalIgnoreCase) >= 0;
                        if (!byThumb && !bySubject)
                            continue;
                        if (match == null || candidate.NotAfter > match.NotAfter)
                            match = candidate;
                    }
                    return match;
                });

                if (cert != null)
                    return cert;
            }

            return null;
        }

        private static T Read<T>(StoreLocation location, string storeName, Func<X509Certificate2Collection, T> read)
        {
            try
            {
                using (var store = new X509Store(storeName, location))
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    return read(store.Certificates);
                }
            }
            catch
            {
                return default(T);
            }
        }
    }
}
