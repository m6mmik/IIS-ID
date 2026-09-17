using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Demo.Contracts;
using Microsoft.Win32;

namespace Demo.CertProbe
{
    internal sealed class ProbeContext
    {
        public string Remote;
        public string RequestLine;
        public string TlsProtocol;
        public string TlsCipher;
        public SslPolicyErrors SchannelErrors;
        public X509Certificate2 ClientCertificate;
        public string HandshakeError;
    }

    /// <summary>
    /// Kogu "miks PIN1 ei õnnestunud" analüüs ühes tekstis.
    /// Probe usaldab iga kliendisertifikaati, seetõttu jõuame ahela ehitamiseni ka siis,
    /// kui HTTP.sys oleks kätluse juures 403.16-ga katkestanud.
    /// </summary>
    internal static class CertificateReport
    {
        public static string Build(ProbeContext context)
        {
            var body = new StringBuilder();
            var verdict = new List<string>();
            var actions = new List<string>();

            Section(body, "1. TLS KATLUS");
            if (context.HandshakeError != null)
            {
                body.AppendLine("  Katlus ebaonnestus: " + context.HandshakeError);
                verdict.Add("[KATLUS] TLS ei jounud loppu. Klient ei saatnud serti voi ei usalda probe serveri serti.");
                actions.Add("Kui klient ei usalda probe serti: lisa sama server-sert kliendi Trusted Root hoidlasse.");
                actions.Add("Kui klient ei saatnud serti: kaart ei ole lugejas voi valitud sert ei sobi (EKU / valjastaja filter).");
                return Compose(context, verdict, actions, body);
            }

            body.AppendLine("  Protokoll         : " + context.TlsProtocol);
            body.AppendLine("  Cipher            : " + context.TlsCipher);
            body.AppendLine("  Paring            : " + (context.RequestLine ?? "(tuhi)"));
            body.AppendLine("  Schannel hinnang  : " + context.SchannelErrors);
            body.AppendLine("  (probe vottis serdi vastu ka veaga; HTTP.sys sama veaga vastaks 403.16)");

            var leaf = context.ClientCertificate;
            if (leaf == null)
            {
                Section(body, "2. KLIENDI SERTIFIKAAT");
                body.AppendLine("  Klient EI SAATNUD sertifikaati.");
                verdict.Add("[403.7] Kliendisertifikaat ei joudnud serverisse.");
                actions.Add("Kontrolli, kas kaart on lugejas ja kas klient valis PIN1 serdi.");
                actions.Add("IIS-is: netsh http show sslcert -> Negotiate Client Certificate peab olema Enabled.");
                actions.Add("Load balancer ei tohi TLS-i lopetada (HAProxy: mode tcp, ilma 'ssl' server-real).");
                return Compose(context, verdict, actions, body);
            }

            WriteLeaf(body, leaf);
            var chain = WriteTrustChain(body, leaf, verdict, actions);
            var revocation = WriteRevocation(body, leaf, chain, verdict, actions);
            WriteMachineSettings(body, verdict, actions);
            WritePolicy(body, leaf, verdict, actions);

            if (verdict.Count == 0)
            {
                verdict.Add(revocation == RevocationState.Skipped
                    ? "[OK] Ahel on usaldatud. Tuhistust ei kontrollitud: sertifikaadil puudub OCSP/CRL viide (lab-sert)."
                    : "[OK] Ahel on usaldatud ja tuhistus vastas. IIS peaks selle serdi vastu votma.");
                actions.Add("Kui WCF ikka annab 403: vaata IIS-i alamstaatust (Get-EidReport.ps1) ja sslFlags seadeid.");
            }

            return Compose(context, verdict, actions, body);
        }

        private static void WriteLeaf(StringBuilder body, X509Certificate2 leaf)
        {
            Section(body, "2. KLIENDI SERTIFIKAAT (PIN1 leht)");
            body.AppendLine("  Subject     : " + leaf.Subject);
            body.AppendLine("  Issuer      : " + leaf.Issuer);
            body.AppendLine("  Serial      : " + leaf.SerialNumber);
            body.AppendLine("  Kehtiv      : " + leaf.NotBefore.ToString("u") + "  ...  " + leaf.NotAfter.ToString("u"));
            body.AppendLine("  Thumbprint  : " + leaf.Thumbprint);
            body.AppendLine("  Isikukood   : " + (CertificateInspector.GetPersonalCode(leaf) ?? "(ei leitud subjectist)"));
            body.AppendLine("  Client Auth EKU : " + CertificateInspector.IsAuthenticationCertificate(leaf));
            body.AppendLine("  NonRepudiation  : " + CertificateInspector.IsSigningCertificate(leaf) + "  (PIN2 sert, ei sobi TLS-i)");

            var policies = CertificateInspector.GetPolicyOids(leaf);
            body.AppendLine("  Poliitika OID-d : " + (policies.Count == 0 ? "(puuduvad)" : string.Join(", ", policies)));

            if (DateTime.Now > leaf.NotAfter)
                body.AppendLine("  HOIATUS: sertifikaat on AEGUNUD.");
            if (DateTime.Now < leaf.NotBefore)
                body.AppendLine("  HOIATUS: sertifikaat ei ole veel kehtiv (kontrolli serveri kella).");
        }

        private static X509Chain WriteTrustChain(StringBuilder body, X509Certificate2 leaf,
            List<string> verdict, List<string> actions)
        {
            Section(body, "3. AHEL JA HOIDLAD (ilma tuhistuskontrollita)");
            var chain = new X509Chain(true);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
            var ok = chain.Build(leaf);

            body.AppendLine("  Tulemus     : " + (ok ? "USALDATUD" : "EI OLE USALDATUD"));
            body.AppendLine("  Lulisid     : " + chain.ChainElements.Count);
            body.AppendLine();

            for (var i = 0; i < chain.ChainElements.Count; i++)
            {
                var element = chain.ChainElements[i];
                var stores = CertificateStores.Locate(element.Certificate);
                body.AppendLine("  [" + i + "] " + ShortName(element.Certificate.Subject));
                body.AppendLine("      hoidlad : " + (stores.Count == 0
                    ? (i == 0 ? "(kaardi leht - normaalne, seda hoidlas ei ole)" : "PUUDUB KOIGIST HOIDLATEST")
                    : string.Join(", ", stores)));
                foreach (var status in element.ChainElementStatus)
                    body.AppendLine("      viga    : " + status.Status + " - " + status.StatusInformation.Trim());
            }

            if (ok)
                return chain;

            var flags = chain.ChainStatus.Select(s => s.Status).ToList();
            body.AppendLine();
            body.AppendLine("  Ahela staatus: " + string.Join(", ", flags));

            var partial = flags.Contains(X509ChainStatusFlags.PartialChain) || chain.ChainElements.Count < 2;
            var untrustedRoot = flags.Contains(X509ChainStatusFlags.UntrustedRoot);

            if (partial)
            {
                verdict.Add("[403.16] Ahel on katkine: valjastajat ei leitud selle masina hoidlatest.");
                var issuer = ShortName(leaf.Issuer);
                actions.Add("Paigalda vahepealne CA (" + issuer + ") hoidlatesse LocalMachine\\CA JA LocalMachine\\ClientAuthIssuer.");
                actions.AddRange(CertUtilHints(leaf.Issuer));
            }
            else if (untrustedRoot)
            {
                verdict.Add("[403.16] Juurika ei ole usaldatud (LocalMachine\\Root).");
                actions.Add("Paigalda EE-GovCA2018 / EEGovCA2025 hoidlasse LocalMachine\\Root.");
                actions.Add("certutil -addstore -f Root EE-GovCA2018.der.crt");
            }
            else
            {
                verdict.Add("[403.16] Ahela ehitamine ebaonnestus: " + string.Join(", ", flags));
            }

            actions.Add("Skript: powershell -File scripts\\Install-EsteidIisProduction.ps1  (toodangu hoidlate paigutus)");
            return chain;
        }

        private static RevocationState WriteRevocation(StringBuilder body, X509Certificate2 leaf, X509Chain trustChain,
            List<string> verdict, List<string> actions)
        {
            Section(body, "4. TUHISTUS (OCSP / CRL)");
            if (trustChain == null || trustChain.ChainElements.Count < 2)
            {
                body.AppendLine("  Vahele jaetud: ahel ei ole terve, tuhistust ei ole mottet kusida.");
                return RevocationState.NoChain;
            }

            var urls = RevocationUrls(leaf);
            if (urls.Count == 0)
            {
                body.AppendLine("  Sertifikaadil EI OLE OCSP ega CRL viidet (tuupiline test-CA / lab-sert).");
                body.AppendLine("  Tuhistust ei saa pohimotteliselt kontrollida.");
                body.AppendLine("  Toodangus, kus verifyclientcertrevocation=enable, annaks selline sert 403.13.");
                body.AppendLine("  Paris ID-kaardil on AIA/OCSP viide olemas - siis on see kontroll asjakohane.");
                return RevocationState.Skipped;
            }

            body.AppendLine("  Sertifikaadi tuhistus-URL-id (need peavad selle masina jaoks avatud olema):");
            foreach (var url in urls)
                body.AppendLine("    " + url);
            body.AppendLine();

            var chain = new X509Chain(true);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(15);

            var started = DateTime.UtcNow;
            var ok = chain.Build(leaf);
            var took = (DateTime.UtcNow - started).TotalMilliseconds;

            body.AppendLine("  Tulemus     : " + (ok ? "OK" : "EBAONNESTUS"));
            body.AppendLine("  Kestus      : " + took.ToString("F0") + " ms  (aeglane = OCSP/proxy ei vasta)");

            var flags = chain.ChainStatus.Select(s => s.Status).ToList();
            if (flags.Count > 0)
                body.AppendLine("  Staatus     : " + string.Join(", ", flags));
            foreach (var element in chain.ChainElements)
                foreach (var status in element.ChainElementStatus)
                    body.AppendLine("    " + ShortName(element.Certificate.Subject) + " -> " +
                                    status.Status + " - " + status.StatusInformation.Trim());

            if (ok)
                return RevocationState.Ok;

            if (flags.Contains(X509ChainStatusFlags.Revoked))
            {
                verdict.Add("[TUHISTATUD] Sertifikaat on tuhistatud. See ei ole seadistusviga.");
                return RevocationState.Failed;
            }

            if (flags.Contains(X509ChainStatusFlags.RevocationStatusUnknown) ||
                flags.Contains(X509ChainStatusFlags.OfflineRevocation))
            {
                verdict.Add("[403.13] Ahel on usaldatud, aga tuhistuse kontroll ei onnestunud (OCSP/CRL ei vastanud).");
                actions.Add("Luba sellelt masinalt valjuv HTTP 80: aia.sk.ee, ocsp.eidpki.ee, c.sk.ee (OCSP ei ole 443).");
                actions.Add("netsh winhttp show proxy  -> HTTP.sys ja CAPI2 kasutavad SEDA, mitte IE ega Web.config proxyt.");
                actions.Add("Tuhista vahemalu enne uut katset: certutil -urlcache * delete");
            }

            return RevocationState.Failed;
        }

        private static void WriteMachineSettings(StringBuilder body, List<string> verdict, List<string> actions)
        {
            Section(body, "5. SELLE MASINA SEADED");
            var issuerCount = CertificateStores.Count(StoreLocation.LocalMachine, "ClientAuthIssuer");
            var issuerEsteid = CertificateStores.CountMatching(StoreLocation.LocalMachine, "ClientAuthIssuer", "ESTEID");
            var caEsteid = CertificateStores.CountMatching(StoreLocation.LocalMachine, "CA", "ESTEID");
            var rootGov = CertificateStores.CountMatching(StoreLocation.LocalMachine, "Root", "EE-GovCA", "EEGovCA", "EE Certification");

            body.AppendLine("  LocalMachine\\ClientAuthIssuer : " + issuerCount + " serti, neist ESTEID " + issuerEsteid);
            body.AppendLine("  LocalMachine\\CA (ESTEID)      : " + caEsteid);
            body.AppendLine("  LocalMachine\\Root (EE-Gov)    : " + rootGov);

            var schannel = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL");
            var trustMode = schannel != null ? schannel.GetValue("ClientAuthTrustMode") : null;
            var issuerList = schannel != null ? schannel.GetValue("SendTrustedIssuerList") : null;
            body.AppendLine("  SCHANNEL ClientAuthTrustMode   : " + (trustMode ?? "(pole seatud, vaikimisi 0)"));
            body.AppendLine("  SCHANNEL SendTrustedIssuerList : " + (issuerList ?? "(pole seatud)"));

            if (issuerCount == 0)
            {
                verdict.Add("[403.16 risk] LocalMachine\\ClientAuthIssuer on TUHI. IIS 8+ vaatab sealt lubatud valjastajaid.");
                actions.Add("certutil -addstore -f ClientAuthIssuer esteid2018.der.crt   (ja ESTEID2025)");
            }
            else if (issuerEsteid == 0)
            {
                verdict.Add("[403.16 risk] ClientAuthIssuer ei sisalda ESTEID valjastajaid.");
            }
        }

        private static void WritePolicy(StringBuilder body, X509Certificate2 leaf,
            List<string> verdict, List<string> actions)
        {
            Section(body, "6. RAKENDUSE POLIITIKA (see on WCF kood, mitte HTTP.sys)");
            var lab = CertificateReportOptions.AllowLabCertificates;
            var result = CertificateInspector.CheckAuthenticationPolicy(leaf, lab);
            body.AppendLine("  AllowLabCertificates : " + lab);
            body.AppendLine("  Otsus                : " + (result.Accepted ? "LUBATUD" : "TAGASI LUKATUD"));
            body.AppendLine("  Pohjus               : " + result.Reason);

            if (!result.Accepted)
            {
                verdict.Add("[200 + WCF Fault] HTTP.sys lubaks labi, aga rakenduse poliitika-kontroll lukkab tagasi.");
                actions.Add("See ei ole 403: vaata teenuse EsteidPolicies OID-de nimekirja ja AllowLabCertificates seadet.");
            }
        }

        /// <summary>AIA (OCSP) ja CDP (CRL) URL-id lehe pealt. Ilma nendeta ei ole tuhistuskontroll voimalik.</summary>
        private static List<string> RevocationUrls(X509Certificate2 leaf)
        {
            var urls = new List<string>();
            foreach (var extension in leaf.Extensions)
            {
                if (extension.Oid == null)
                    continue;
                if (extension.Oid.Value != "1.3.6.1.5.5.7.1" && extension.Oid.Value != "2.5.29.31")
                    continue;

                var text = extension.Format(true) ?? string.Empty;
                foreach (System.Text.RegularExpressions.Match match in
                    System.Text.RegularExpressions.Regex.Matches(text, @"https?://[^\s,;)\]]+"))
                {
                    var url = match.Value.TrimEnd('.', ',');
                    if (!urls.Contains(url))
                        urls.Add(url);
                }
            }
            return urls;
        }

        private static IEnumerable<string> CertUtilHints(string issuer)
        {
            var hints = new List<string>();
            if (issuer == null)
                return hints;

            if (issuer.IndexOf("ESTEID2018", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                hints.Add("certutil -addstore -f CA esteid2018.der.crt               (https://c.sk.ee/esteid2018.der.crt)");
                hints.Add("certutil -addstore -f ClientAuthIssuer esteid2018.der.crt");
                hints.Add("certutil -addstore -f Root EE-GovCA2018.der.crt           (https://c.sk.ee/EE-GovCA2018.der.crt)");
            }
            else if (issuer.IndexOf("ESTEID2025", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                hints.Add("certutil -addstore -f CA ESTEID2025.crt                   (https://crt.eidpki.ee/ESTEID2025.crt)");
                hints.Add("certutil -addstore -f ClientAuthIssuer ESTEID2025.crt");
                hints.Add("certutil -addstore -f Root EEGovCA2025.crt                (https://crt.eidpki.ee/EEGovCA2025.crt)");
            }
            else
            {
                hints.Add("Valjastaja ei ole ESTEID2018/2025: kontrolli, kas tegu on labi test-CA voi mone muu kaardiga.");
            }

            return hints;
        }

        private static string Compose(ProbeContext context, List<string> verdict, List<string> actions, StringBuilder body)
        {
            var sb = new StringBuilder();
            var line = new string('=', 78);
            sb.AppendLine(line);
            sb.AppendLine("IIS-ID CertProbe raport");
            sb.AppendLine("Aeg    : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  (" + TimeZoneInfo.Local.StandardName + ")");
            sb.AppendLine("Masin  : " + Environment.MachineName + "   Kasutaja: " + Environment.UserName);
            sb.AppendLine("Klient : " + context.Remote);
            sb.AppendLine(line);
            sb.AppendLine();
            sb.AppendLine("VERDIKT");
            foreach (var item in verdict)
                sb.AppendLine("  " + item);
            sb.AppendLine();
            sb.AppendLine("MIDA TEHA");
            if (actions.Count == 0)
                sb.AppendLine("  (midagi ei ole vaja parandada)");
            foreach (var item in actions.Distinct())
                sb.AppendLine("  - " + item);
            sb.AppendLine();
            sb.Append(body);
            sb.AppendLine();
            sb.AppendLine("Serveripoolne koondraport (IIS logid, CAPI2, HTTPERR, Schannel):");
            sb.AppendLine("  powershell -ExecutionPolicy Bypass -File scripts\\Get-EidReport.ps1");
            sb.AppendLine(line);
            return sb.ToString();
        }

        private static void Section(StringBuilder body, string title)
        {
            body.AppendLine();
            body.AppendLine(title);
            body.AppendLine(new string('-', title.Length));
        }

        private static string ShortName(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName))
                return "(tundmatu)";
            var parts = distinguishedName.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3);
            }
            return distinguishedName;
        }
    }

    internal enum RevocationState
    {
        Ok,
        Skipped,
        Failed,
        NoChain
    }

    internal static class CertificateReportOptions
    {
        public static bool AllowLabCertificates = true;
    }
}
