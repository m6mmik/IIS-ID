using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Demo.CertProbe
{
    /// <summary>
    /// Diagnostikakuulaja: teeb mTLS kätluse nagu IIS, aga usaldab iga kliendisertifikaati.
    /// Nii jõuab päring alati raportini ja kasutaja näeb ühel lehel, miks HTTP.sys 403.16 annaks.
    /// Käivita sellel masinal, kus IIS on. Ava aadress kaardiga: https://masin:9444/
    /// </summary>
    internal static class Program
    {
        private static readonly object LogLock = new object();
        private static X509Certificate2 _serverCert;
        private static string _logPath;

        private static int Main(string[] args)
        {
            try
            {
                var port = int.Parse(Read(args, "--port") ?? "9444", CultureInfo.InvariantCulture);
                var certReference = Read(args, "--cert") ?? "demo.local";
                _logPath = Read(args, "--log") ?? DefaultLogPath();
                CertificateReportOptions.AllowLabCertificates = !Has(args, "--strict-policy");

                _serverCert = CertificateStores.FindServerCertificate(certReference);
                if (_serverCert == null)
                {
                    Console.Error.WriteLine("Serveri sertifikaati ei leitud: " + certReference);
                    Console.Error.WriteLine("Kasuta --cert <thumbprint voi CN osa>. Sert peab olema My hoidlas ja privaatvotmega.");
                    return 1;
                }

                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();

                Console.WriteLine("Demo.CertProbe");
                Console.WriteLine("  kuulab      : https://" + Environment.MachineName + ":" + port + "/");
                Console.WriteLine("  server-sert : " + _serverCert.Subject + "  (" + _serverCert.Thumbprint + ")");
                Console.WriteLine("  logi        : " + _logPath);
                Console.WriteLine();
                Console.WriteLine("Ava see aadress ID-kaardiga (brauser voi klient). Vastuseks tuleb raport:");
                Console.WriteLine("kas ahel ehitub, millisest hoidlast iga luli tuleb ja mida IIS teeks (403.7/13/16).");
                Console.WriteLine("Ctrl+C peatab.");
                Console.WriteLine();

                while (true)
                {
                    var client = listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(_ => Handle(client));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("CertProbe: " + ex.Message);
                return 1;
            }
        }

        private static void Handle(TcpClient client)
        {
            var context = new ProbeContext { Remote = "?" };
            try
            {
                context.Remote = client.Client.RemoteEndPoint.ToString();
                client.ReceiveTimeout = 8000;
                client.SendTimeout = 8000;

                using (var ssl = new SslStream(client.GetStream(), false, (s, cert, chain, errors) =>
                {
                    context.SchannelErrors = errors;
                    return true;
                }))
                {
                    try
                    {
                        ssl.AuthenticateAsServer(_serverCert, true, SslProtocols.None, false);
                        context.TlsProtocol = ssl.SslProtocol.ToString();
                        context.TlsCipher = ssl.CipherAlgorithm + "/" + ssl.HashAlgorithm;
                        if (ssl.RemoteCertificate != null)
                        {
                            context.ClientCertificate = new X509Certificate2(ssl.RemoteCertificate);
                            SaveClientCertificate(context.ClientCertificate);
                        }
                        context.RequestLine = ReadRequestLine(ssl);
                    }
                    catch (Exception ex)
                    {
                        context.HandshakeError = Flatten(ex);
                    }

                    var report = CertificateReport.Build(context);
                    Console.WriteLine(report);
                    Append(report);

                    if (context.HandshakeError == null)
                        WriteHttp(ssl, report);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("probe: uhendus katkes (" + ex.Message + ")");
            }
            finally
            {
                try { client.Close(); } catch { }
            }
        }

        private static string ReadRequestLine(SslStream ssl)
        {
            try
            {
                ssl.ReadTimeout = 3000;
                var buffer = new byte[2048];
                var read = ssl.Read(buffer, 0, buffer.Length);
                if (read <= 0)
                    return null;
                var text = Encoding.ASCII.GetString(buffer, 0, read);
                var end = text.IndexOf('\r');
                return end > 0 ? text.Substring(0, end) : text.Trim();
            }
            catch
            {
                return null;
            }
        }

        private static void WriteHttp(SslStream ssl, string report)
        {
            try
            {
                var body = Encoding.UTF8.GetBytes(report);
                var header = new StringBuilder();
                header.Append("HTTP/1.1 200 OK\r\n");
                header.Append("Content-Type: text/plain; charset=utf-8\r\n");
                header.Append("Content-Length: " + body.Length + "\r\n");
                header.Append("Cache-Control: no-store\r\n");
                header.Append("Connection: close\r\n\r\n");
                var head = Encoding.ASCII.GetBytes(header.ToString());
                ssl.Write(head, 0, head.Length);
                ssl.Write(body, 0, body.Length);
                ssl.Flush();
            }
            catch
            {
                // klient laks ara, raport on logis olemas
            }
        }

        private static void Append(string report)
        {
            try
            {
                lock (LogLock)
                {
                    var dir = Path.GetDirectoryName(_logPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    File.AppendAllText(_logPath, report + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch
            {
                // logi ei tohi diagnostikat maha vetta
            }
        }

        /// <summary>
        /// Salvestab viimase nahtud kliendiserdi korvale logi. Get-EidReport.ps1 votab
        /// selle ette ja laseb sellel "certutil -verify -urlfetch" - see naitab, kas
        /// AIA/OCSP/CRL URL-id vastavad selle masina vorgust (proxy 407, MITM, aegumine).
        /// </summary>
        private static void SaveClientCertificate(X509Certificate2 cert)
        {
            try
            {
                var dir = Path.GetDirectoryName(_logPath);
                if (string.IsNullOrEmpty(dir))
                    return;
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                File.WriteAllBytes(Path.Combine(dir, "lastclient.cer"), cert.Export(X509ContentType.Cert));
            }
            catch
            {
                // diagnostika ei tohi selle parast katkeda
            }
        }

        private static string DefaultLogPath()
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "lab.ps1")))
                    return Path.Combine(dir.FullName, ".lab", "certprobe.log");
                dir = dir.Parent;
            }

            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "IIS-ID", "certprobe.log");
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

        private static bool Has(string[] args, string name)
        {
            foreach (var arg in args)
                if (string.Equals(arg, name, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private static string Read(string[] args, string name)
        {
            for (var i = 0; i < args.Length - 1; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            return null;
        }
    }
}
