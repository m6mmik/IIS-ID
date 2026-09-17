using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Demo.Client
{
    /// <summary>
    /// Kliendipoolne diagnostika. WCF peidab tegeliku HTTP staatuse teate taha
    /// "client authentication scheme 'Anonymous'". Siin teeme sama kätluse käsitsi
    /// ja näitame ära, mida server päriselt vastas: kas serti üldse küsiti (403.7),
    /// kas ahel lükati tagasi (403.16) või kas tühistus ebaõnnestus (403.13).
    /// </summary>
    internal static class ClientDiagnostics
    {
        private static readonly object LogLock = new object();

        // BOM-iga UTF-8: ilma selleta loevad Notepad ja PowerShell 5.1 täpitähed katki.
        private static readonly Encoding LogEncoding = new UTF8Encoding(true);

        public static string LogPath
        {
            get
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "IIS-ID");
                return Path.Combine(dir, "client.log");
            }
        }

        public static void Log(string line)
        {
            try
            {
                lock (LogLock)
                {
                    var dir = Path.GetDirectoryName(LogPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    if (!File.Exists(LogPath))
                        File.WriteAllBytes(LogPath, LogEncoding.GetPreamble());
                    File.AppendAllText(LogPath,
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + line + Environment.NewLine,
                        LogEncoding);
                }
            }
            catch
            {
                // logimine ei tohi klienti maha võtta
            }
        }

        public static DiagnosticsResult Run(string address, X509Certificate2 authCert)
        {
            var report = new StringBuilder();
            var verdicts = new System.Collections.Generic.List<string>();

            report.AppendLine("Klient: " + Environment.MachineName + " / " + Environment.UserName);
            report.AppendLine("Aadress: " + address);
            report.AppendLine("PIN1 sert: " + (authCert == null ? "(puudub)" : authCert.Subject));
            if (authCert != null)
                report.AppendLine("  väljastaja: " + authCert.Issuer + "  thumb: " + authCert.Thumbprint);
            report.AppendLine();

            // HTTP proov käib ka siis, kui käsitsi kätlus kukkus: HttpWebRequest saab
            // sageli ikkagi vastuse kätte ja just seal on päris alamstaatus.
            var tcpOk = ProbeTls(address, authCert, report, verdicts);
            if (tcpOk)
                ProbeHttp(address, authCert, report, verdicts);

            if (verdicts.Count == 0)
                verdicts.Add("Transport on korras. Kui viga püsib, on see WCF/SOAP või rakenduse poliitika tasand, mitte mTLS.");

            var result = new DiagnosticsResult
            {
                Verdict = string.Join(Environment.NewLine, verdicts),
                Detail = report.ToString()
            };

            Log("DIAGNOSTIKA " + address);
            foreach (var line in result.Detail.Split('\n'))
                Log("  " + line.TrimEnd('\r'));
            Log("VERDIKT: " + result.Verdict.Replace(Environment.NewLine, " | "));
            return result;
        }

        private static bool ProbeTls(string address, X509Certificate2 authCert,
            StringBuilder report, System.Collections.Generic.List<string> verdicts)
        {
            report.AppendLine("1. TLS kätlus (ilma WCF-ita)");
            if (authCert == null)
                report.AppendLine("   (diagnostika käivitati ilma PIN1 serdita — nii näeb, mida server anonüümselt vastab)");
            var uri = new Uri(address);

            // .NET Framework 4.8 SslStream ei oska TLS 1.3 kliendisertifikaati (annab
            // "m_safeCertContext is an invalid handle"), seega proovime esmalt TLS 1.2 —
            // sama, mida WCF klient päriselt räägib. Kui server 1.2 ei võta, proovime uuesti.
            var outcome = Handshake(uri, authCert, SslProtocols.Tls12);
            if (!outcome.Completed && !outcome.CertRequested && !outcome.TcpFailed)
            {
                report.AppendLine("   TLS 1.2 ei sobinud (" + outcome.Error + "), proovin serveri valikuga uuesti");
                outcome = Handshake(uri, authCert, SslProtocols.None);
            }

            if (outcome.TcpFailed)
            {
                report.AppendLine("   TCP ei avanenud: " + uri.Host + ":" + uri.Port);
                verdicts.Add("TCP ühendust ei saa: load balancer ei jookse või port on kinni. See ei ole sertifikaadi probleem.");
                return false;
            }

            report.AppendLine("   TCP OK " + uri.Host + ":" + uri.Port);
            report.AppendLine("   Protokoll         : " + outcome.Protocol);
            report.AppendLine("   Server küsis serti: " + outcome.CertRequested);
            report.AppendLine("   Klient saatis serdi: " + outcome.CertSent);
            if (!string.IsNullOrEmpty(outcome.ServerSubject))
                report.AppendLine("   Serveri sert      : " + outcome.ServerSubject);
            report.AppendLine("   Serveri serdi vead: " + outcome.SslErrors);

            if (outcome.AcceptableIssuers != null && outcome.AcceptableIssuers.Length > 0)
            {
                report.AppendLine("   Server saatis lubatud väljastajate loendi (SendTrustedIssuerList=1):");
                foreach (var issuer in outcome.AcceptableIssuers)
                    report.AppendLine("     " + issuer);
            }
            else if (outcome.CertRequested)
            {
                report.AppendLine("   Väljastajate loendit ei saadetud (SendTrustedIssuerList=0) — klient pakub kõiki serte.");
            }

            if (!outcome.Completed)
                report.AppendLine("   Kätlus ebaõnnestus: " + outcome.Error);
            report.AppendLine();

            if (!outcome.CertRequested)
            {
                if (outcome.Completed)
                {
                    verdicts.Add("Server EI KÜSINUD kliendisertifikaati. Serverile jõuab päring anonüümsena → 403.7. " +
                                 "Kontrolli HTTP.sys 'Negotiate Client Certificate' ja seda, et load balancer ei lõpetaks TLS-i.");
                }
                else
                {
                    verdicts.Add("TLS kätlus ei õnnestunud enne serdi küsimist. Kontrolli TLS versioone " +
                                 "(ära keela TLS 1.2, kui klient on .NET 4.8) ja seda, kas serveri sert vastab aadressi nimele.");
                }
            }
            else if (!outcome.CertSent)
            {
                verdicts.Add("Server küsis kliendisertifikaati, aga klient ei saatnud ühtegi: kaart ei ole lugejas, " +
                             "sert on valimata või see ei sobinud väljastajate filtriga. Server logib selle 403.7-na.");
            }
            else if (!outcome.Completed)
            {
                verdicts.Add("Server katkestas kätluse PÄRAST seda, kui sert oli saadetud. See on tüüpiline 403.16 muster: " +
                             "Schannel ei usalda selle serdi ahelat. Vaata serveri raportit (Get-EidReport.ps1) ja hoidlaid.");
            }

            return true;
        }

        private sealed class HandshakeOutcome
        {
            public bool TcpFailed;
            public bool Completed;
            public bool CertRequested;
            public bool CertSent;
            public string[] AcceptableIssuers;
            // Ainult tekst: serdi objekt muutub kehtetuks, kui SslStream on suletud.
            public string ServerSubject;
            public SslPolicyErrors SslErrors;
            public SslProtocols Protocol;
            public string Error;
        }

        private static HandshakeOutcome Handshake(Uri uri, X509Certificate2 authCert, SslProtocols protocols)
        {
            var outcome = new HandshakeOutcome();
            try
            {
                using (var tcp = new TcpClient())
                {
                    var connect = tcp.BeginConnect(uri.Host, uri.Port, null, null);
                    if (!connect.AsyncWaitHandle.WaitOne(5000) || !tcp.Connected)
                    {
                        outcome.TcpFailed = true;
                        return outcome;
                    }
                    tcp.EndConnect(connect);

                    using (var ssl = new SslStream(tcp.GetStream(), false,
                        (s, cert, chain, errors) =>
                        {
                            outcome.ServerSubject = cert == null ? null : cert.Subject;
                            outcome.SslErrors = errors;
                            return true;
                        },
                        (s, host, local, remote, issuers) =>
                        {
                            outcome.CertRequested = true;
                            outcome.AcceptableIssuers = issuers;
                            return authCert;
                        }))
                    {
                        var certs = new X509CertificateCollection();
                        if (authCert != null)
                            certs.Add(authCert);

                        ssl.AuthenticateAsClient(uri.Host, certs, protocols, false);

                        outcome.Completed = true;
                        outcome.Protocol = ssl.SslProtocol;
                        outcome.CertSent = ssl.LocalCertificate != null;
                    }
                }
            }
            catch (Exception ex)
            {
                outcome.Error = Flatten(ex);
                outcome.CertSent = outcome.CertRequested && authCert != null;
            }
            return outcome;
        }

        private static void ProbeHttp(string address, X509Certificate2 authCert,
            StringBuilder report, System.Collections.Generic.List<string> verdicts)
        {
            report.AppendLine("2. HTTP vastus (päris staatus, mida WCF ära peidab)");
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                var request = (HttpWebRequest)WebRequest.Create(address);
                request.Method = "GET";
                request.Timeout = 15000;
                request.KeepAlive = false;
                request.ServerCertificateValidationCallback = (s, c, ch, e) => true;
                if (authCert != null)
                    request.ClientCertificates.Add(authCert);

                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    report.AppendLine("   Staatus: " + (int)response.StatusCode + " " + response.StatusDescription);
                    report.AppendLine("   (GET .svc peale ei ole SOAP — 200/400/415 tähendab, et mTLS läbis)");
                    verdicts.Add("mTLS läbis: server võttis PIN1 serdi vastu (HTTP " + (int)response.StatusCode + ").");
                }
            }
            catch (WebException ex)
            {
                var response = ex.Response as HttpWebResponse;
                if (response == null)
                {
                    report.AppendLine("   Transpordi viga: " + Flatten(ex));
                    verdicts.Add("HTTP päring ei jõudnud vastuseni: " + ex.Status + ".");
                    return;
                }

                var status = (int)response.StatusCode;
                var body = ReadBody(response);
                var subStatus = FindSubStatus(body);
                report.AppendLine("   Staatus: " + status + " " + response.StatusDescription);
                report.AppendLine("   Alamstaatus kehast: " + (subStatus ?? "(server ei näidanud)"));
                if (!string.IsNullOrEmpty(body))
                {
                    var snippet = Regex.Replace(body, "<[^>]+>", " ");
                    snippet = Regex.Replace(snippet, @"\s+", " ").Trim();
                    if (snippet.Length > 300)
                        snippet = snippet.Substring(0, 300) + "...";
                    report.AppendLine("   Keha: " + snippet);
                }

                if (status == 403)
                    verdicts.Add(Explain403(subStatus));
                else
                    verdicts.Add("Server vastas " + status + ". See ei ole kliendisertifikaadi tõrge.");
            }
            catch (Exception ex)
            {
                report.AppendLine("   Viga: " + Flatten(ex));
            }
            report.AppendLine();
        }

        private static string Explain403(string subStatus)
        {
            switch (subStatus)
            {
                case "403.7":
                    return "403.7 — server nõuab kliendisertifikaati, aga ei saanud seda. " +
                           "HTTP.sys 'Negotiate Client Certificate' on väljas või load balancer lõpetas TLS-i.";
                case "403.16":
                    return "403.16 — sert JÕUDIS serverisse, aga selle masina usaldusahel ei ole korras. " +
                           "Paranda ESTEID2018/2025 hoidlates CA + ClientAuthIssuer ja EE-GovCA Root hoidlas. " +
                           "Tõesta ära: Demo.CertProbe.exe sellel serveril.";
                case "403.13":
                    return "403.13 — ahel on usaldatud, aga tühistuse kontroll (OCSP/CRL) ebaõnnestus. " +
                           "Serveril peab olema väljuv HTTP 80 SK/eidpki peale või WinHTTP proxy.";
                default:
                    return "403, aga server ei näidanud alamstaatust. Serveris: Get-EidReport.ps1 (IIS logi sc-substatus) " +
                           "või luba ajutiselt httpErrors errorMode=\"Detailed\". Alamstaatus 7/13/16 ütleb, kus viga on.";
            }
        }

        private static string FindSubStatus(string body)
        {
            if (string.IsNullOrEmpty(body))
                return null;
            var match = Regex.Match(body, @"403\.(\d+)");
            return match.Success ? "403." + match.Groups[1].Value : null;
        }

        private static string ReadBody(HttpWebResponse response)
        {
            try
            {
                using (var stream = response.GetResponseStream())
                {
                    if (stream == null)
                        return null;
                    using (var reader = new StreamReader(stream))
                        return reader.ReadToEnd();
                }
            }
            catch
            {
                return null;
            }
        }

        private static string Flatten(Exception ex)
        {
            var sb = new StringBuilder();
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (sb.Length > 0)
                    sb.Append(" -> ");
                sb.Append(e.Message);
            }
            return sb.ToString();
        }
    }

    internal sealed class DiagnosticsResult
    {
        public string Verdict { get; set; }
        public string Detail { get; set; }
    }
}
