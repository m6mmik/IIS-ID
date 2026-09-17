using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Hosting;
using Demo.Contracts;

namespace Demo.Service
{
    /// <summary>
    /// Üks rakenduse logifail (App_Data\service.log). Siia jõuab see, mis juhtub
    /// PÄRAST edukat mTLS-i: milline sert tuli, milline backend vastas, kas poliitika läbis.
    /// Kui siin ei ole ühtegi rida, ei jõudnud päring WCF-ini — siis on viga HTTP.sys / IIS tasemel
    /// ja vastus on IIS-i alamstaatuses (403.7 / 403.13 / 403.16).
    /// </summary>
    public static class ServiceLog
    {
        private static readonly object Gate = new object();
        private static string _path;

        // BOM-iga UTF-8: ilma selleta loevad Notepad ja PowerShell 5.1 täpitähed katki.
        private static readonly Encoding LogEncoding = new UTF8Encoding(true);

        /// <summary>
        /// Vaikimisi App_Data\service.log. Toodangus pane appSetting "serviceLogPath"
        /// rakendusest VÄLJAPOOLE (nt D:\logs\demo\service.log): siis ei kao logi deploy'ga
        /// ja kirjutamine ei puutu rakenduse kataloogi.
        /// </summary>
        public static string Path
        {
            get
            {
                if (_path != null)
                    return _path;

                var configured = System.Configuration.ConfigurationManager.AppSettings["serviceLogPath"];
                if (!string.IsNullOrEmpty(configured))
                {
                    _path = configured.StartsWith("~")
                        ? HostingEnvironment.MapPath(configured)
                        : configured;
                    return _path;
                }

                var root = HostingEnvironment.ApplicationPhysicalPath;
                if (string.IsNullOrEmpty(root))
                    root = AppDomain.CurrentDomain.BaseDirectory;

                var dir = System.IO.Path.Combine(root, "App_Data");
                _path = System.IO.Path.Combine(dir, "service.log");
                return _path;
            }
        }

        public static void Write(string line)
        {
            var text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + line + Environment.NewLine;

            // Kaks katset: esimene päring võib kataloogi alles luua ja ASP.NET võib
            // sellest tingitud faili-muutuse peale AppDomain'i taaskäivitada.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    lock (Gate)
                    {
                        var dir = System.IO.Path.GetDirectoryName(Path);
                        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                            Directory.CreateDirectory(dir);
                        if (!File.Exists(Path))
                            File.WriteAllBytes(Path, LogEncoding.GetPreamble());
                        File.AppendAllText(Path, text, LogEncoding);
                    }
                    return;
                }
                catch
                {
                    // logimine ei tohi teenust maha võtta
                }
            }
        }

        public static void Call(string operation, string correlationId, X509Certificate2 cert, string outcome)
        {
            var sb = new StringBuilder();
            sb.Append(operation.PadRight(16));
            sb.Append(" correlation=").Append(correlationId ?? "-");
            sb.Append(" backend=").Append(DemoService.GetBackendName());
            sb.Append(" pool=").Append(DemoService.GetAppPool());
            if (cert == null)
            {
                sb.Append(" cert=PUUDUB");
            }
            else
            {
                sb.Append(" cert=").Append(Short(cert.Subject));
                sb.Append(" issuer=").Append(Short(cert.Issuer));
                sb.Append(" thumb=").Append(cert.Thumbprint);
                sb.Append(" isik=").Append(Mask(CertificateInspector.GetPersonalCode(cert)));
            }
            sb.Append(" -> ").Append(outcome);
            Write(sb.ToString());
        }

        /// <summary>Isikukood on isikuandmed: logisse laheb maskitud kuju.</summary>
        private static string Mask(string personalCode)
        {
            if (string.IsNullOrEmpty(personalCode))
                return "-";
            if (personalCode.Length <= 5)
                return new string('*', personalCode.Length);
            return personalCode.Substring(0, 3) + new string('*', personalCode.Length - 5) +
                   personalCode.Substring(personalCode.Length - 2);
        }

        private static string Short(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName))
                return "-";
            foreach (var part in distinguishedName.Split(','))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3);
            }
            return distinguishedName;
        }
    }
}
