using System;
using System.Drawing;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Demo.Contracts;

namespace Demo.Client
{
    internal sealed class MainForm : Form
    {
        private static string DefaultAddress()
        {
            try
            {
                if (System.Deployment.Application.ApplicationDeployment.IsNetworkDeployed)
                    return "https://demo.local:9443/Demo.svc";
            }
            catch
            {
            }
            var cfg = System.Configuration.ConfigurationManager.AppSettings["ServiceAddress"];
            if (!string.IsNullOrWhiteSpace(cfg))
                return cfg;
            return "https://demo.local:9443/Demo.svc";
        }

        private readonly Label _step = new Label();
        private readonly Label _status = new Label();
        private readonly Label _certs = new Label();
        private readonly Button _login = new Button();
        private readonly Button _ping = new Button();
        private readonly TextBox _signText = new TextBox();
        private readonly Button _sign = new Button();
        private readonly Label _signResult = new Label();
        private readonly TextBox _log = new TextBox();
        private readonly TextBox _address = new TextBox();
        private readonly Button _diag = new Button();
        private X509Certificate2 _authCert;
        private X509Certificate2 _signCert;
        private WhoAmIResponse _session;
        private IDemoService _channel;

        public MainForm()
        {
            Text = "ID-kaart: PIN1, tavaline päring, PIN2";
            Width = 720;
            Height = 780;
            MinimumSize = new Size(640, 640);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 10F);

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(20)
            };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.Controls.Add(BuildFlow(), 0, 0);
            root.Controls.Add(BuildAdvanced(), 0, 1);
            root.Controls.Add(BuildLog(), 0, 2);
            Controls.Add(root);

            Load += (_, __) => LoadCerts();
            FormClosed += (_, __) => DemoChannel.Close(_channel);
        }

        private Control BuildFlow()
        {
            var box = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false
            };

            _step.AutoSize = true;
            _step.Font = new Font("Segoe UI", 16F, FontStyle.Bold);
            _step.Text = "Samm 1 / 2 — logi sisse";
            box.Controls.Add(_step);

            _status.AutoSize = true;
            _status.MaximumSize = new Size(640, 0);
            _status.Padding = new Padding(0, 8, 0, 8);
            _status.Text = "Kõigepealt logi sisse (PIN1). Seejärel saad teha tavalisi päringuid või allkirjastada (PIN2).";
            box.Controls.Add(_status);

            _certs.AutoSize = true;
            _certs.MaximumSize = new Size(640, 0);
            _certs.ForeColor = Color.DimGray;
            box.Controls.Add(_certs);

            _login.Text = "1. Logi sisse  (ID-kaart küsib PIN1)";
            _login.Width = 640;
            _login.Height = 48;
            _login.Click += async (_, __) => await Run(_login, LoginAsync);
            box.Controls.Add(_login);

            box.Controls.Add(Heading("Pärast sisselogimist — PIN-i enam ei küsita"));

            _ping.Text = "Tavaline päring (sama TLS-kanal, ilma PIN1/PIN2-ta)";
            _ping.Width = 640;
            _ping.Height = 40;
            _ping.Enabled = false;
            _ping.Click += async (_, __) => await Run(_ping, PingAsync);
            box.Controls.Add(_ping);

            _signText.Multiline = true;
            _signText.Width = 640;
            _signText.Height = 70;
            _signText.Enabled = false;
            _signText.Text = "Allkirjastan selle teate PIN2-ga.";
            box.Controls.Add(_signText);

            _sign.Text = "2. Allkirjasta  (ID-kaart küsib PIN2)";
            _sign.Width = 640;
            _sign.Height = 48;
            _sign.Enabled = false;
            _sign.Click += async (_, __) => await Run(_sign, SignAsync);
            box.Controls.Add(_sign);

            _signResult.AutoSize = true;
            _signResult.MaximumSize = new Size(640, 0);
            _signResult.Padding = new Padding(0, 8, 0, 0);
            box.Controls.Add(_signResult);
            return box;
        }

        private Control BuildAdvanced()
        {
            var group = new GroupBox
            {
                Text = "Täpsem: aadress ja diagnostika",
                AutoSize = true,
                Dock = DockStyle.Top,
                Padding = new Padding(10),
                Margin = new Padding(0, 16, 0, 8)
            };

            var flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false
            };

            flow.Controls.Add(new Label
            {
                Text = "Teenuse aadress (ära muuda, kui lab jookseb)",
                AutoSize = true,
                ForeColor = Color.DimGray
            });
            _address.Text = DefaultAddress();
            _address.Width = 620;
            flow.Controls.Add(_address);

            _diag.Text = "Diagnostika: mis täpselt ebaõnnestus?";
            _diag.Width = 620;
            _diag.Height = 36;
            _diag.Click += async (_, __) => await Run(_diag, DiagnoseAsync);
            flow.Controls.Add(_diag);

            group.Controls.Add(flow);
            return group;
        }

        private Control BuildLog()
        {
            var wrap = new Panel { Dock = DockStyle.Fill };
            var title = new Label
            {
                Text = "Logi",
                Dock = DockStyle.Top,
                Height = 24
            };
            _log.Multiline = true;
            _log.ReadOnly = true;
            _log.ScrollBars = ScrollBars.Both;
            _log.Dock = DockStyle.Fill;
            _log.Font = new Font("Consolas", 9F);
            wrap.Controls.Add(_log);
            wrap.Controls.Add(title);
            return wrap;
        }

        private static Label Heading(string text)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Padding = new Padding(0, 18, 0, 6)
            };
        }

        private async Task Run(Button button, Func<Task> action)
        {
            button.Enabled = false;
            try { await action(); }
            catch (Exception ex)
            {
                Log(Explain(ex));
                _status.Text = Explain(ex);
                _status.ForeColor = Color.Firebrick;

                if (button != _diag && LooksLikeCertificateProblem(ex))
                {
                    Log("Käivitan diagnostika automaatselt, et näha päris HTTP staatust.");
                    try { await DiagnoseAsync(); }
                    catch (Exception diagError) { Log("Diagnostika ise ebaõnnestus: " + Flatten(diagError)); }
                }
            }
            finally
            {
                button.Enabled = true;
                _ping.Enabled = _session != null;
                _sign.Enabled = _session != null;
                _signText.Enabled = _session != null;
            }
        }

        private void LoadCerts()
        {
            var all = CertificateCatalog.LoadPersonal();
            _authCert = CertificateCatalog.FindAuth(all);
            _signCert = CertificateCatalog.FindSign(all);
            _certs.Text = "PIN1 sertifikaat: " + CertificateCatalog.Describe(_authCert) +
                          Environment.NewLine +
                          "PIN2 sertifikaat: " + CertificateCatalog.Describe(_signCert);
            var idCard = CertificateCatalog.IsEsteid(_authCert);
            _login.Text = idCard
                ? "1. Logi sisse  (ID-kaart küsib PIN1)"
                : "1. Logi sisse  (lab-sertifikaat, PIN-i ei küsita)";
            _sign.Text = idCard
                ? "2. Allkirjasta  (ID-kaart küsib PIN2)"
                : "2. Allkirjasta  (lab-sertifikaat, PIN-i ei küsita)";
            if (_authCert == null)
                Log("Autentimissertifikaati ei leitud. Pane ID-kaart lugejasse või käivita .\\lab.ps1 certs");
            else if (idCard)
                Log("Leitud päris ID-kaart (väljastaja " + _authCert.Issuer + "). PIN1 küsitakse, kui Windows pole PIN-i vahemällu jätnud.");
            else
                Log("Kasutusel on lab-sertifikaat (tarkvaraline võti). PIN1/PIN2 dialooge ei tule — see on oodatav. Päris kaardi jaoks pane kaart lugejasse ja ava klient uuesti.");
        }

        private async Task LoginAsync()
        {
            if (_authCert == null)
                throw new InvalidOperationException("PIN1 sertifikaat puudub.");

            ResetSession();
            var correlation = NewCorrelation();
            Log("Sisselogimine: TLS kätlus PIN1 sertifikaadiga → WhoAmI. correlation=" + correlation);
            var response = await CallAsync(channel => channel.WhoAmI(new WhoAmIRequest
            {
                CorrelationId = correlation
            }));

            _session = response;
            _step.Text = "Sisse logitud — tavaline päring või PIN2";
            _status.ForeColor = Color.DarkGreen;
            _status.Text = string.Format(
                "Sisse logitud: {0}\r\nIsikukood: {1}\r\nServer: {2} (pid {3})\r\nPoliitika: {4}",
                response.AuthCertSubject,
                response.PersonalCode ?? "(puudub)",
                response.BackendName,
                response.ProcessId,
                response.PolicyAccepted ? response.PolicyReason : "tagasi lükatud — " + response.PolicyReason);
            _ping.Enabled = true;
            _sign.Enabled = true;
            _signText.Enabled = true;
            Log("PIN1 OK. Järgmine: tavaline päring (ilma PIN-ita) või allkirjasta (PIN2).");
        }

        private async Task SignAsync()
        {
            if (_session == null)
                throw new InvalidOperationException("Kõigepealt logi sisse (samm 1).");
            if (_signCert == null)
                throw new InvalidOperationException("PIN2 sertifikaat puudub.");

            Log("Allkirjastan lokaalselt. ID-kaart küsib PIN2.");
            var signed = await Task.Run(() => LocalSigner.Sign(_signCert, _signText.Text));
            var result = await CallAsync(channel => channel.SubmitSignature(new SignRequest
            {
                CorrelationId = NewCorrelation(),
                DataUtf8 = _signText.Text,
                Signature = signed.Signature,
                SigningCertificateDer = signed.CertificateDer,
                HashAlgorithm = signed.HashAlgorithm
            }));

            _signResult.ForeColor = result.SignatureValid && result.SamePersonAsAuthCert ? Color.DarkGreen : Color.Firebrick;
            _signResult.Text = result.Message +
                               Environment.NewLine +
                               "Allkiri kehtib: " + result.SignatureValid +
                               ", sama isik PIN1-ga: " + result.SamePersonAsAuthCert +
                               ", server: " + result.BackendName;
            Log(_signResult.Text);
        }

        private async Task PingAsync()
        {
            if (_session == null)
                throw new InvalidOperationException("Kõigepealt logi sisse (samm 1).");

            var correlation = NewCorrelation();
            var result = await CallAsync(channel => channel.Ping(new PingRequest
            {
                CorrelationId = correlation,
                Message = "tavaline paring"
            }));

            Log(string.Format(
                "Tavaline päring OK  correlation={0} backend={1} pid={2} echo={3} aeg={4}",
                correlation, result.BackendName, result.ProcessId, result.Echo, result.ServerTimeUtc));
            if (_session != null && !string.Equals(_session.BackendName, result.BackendName, StringComparison.Ordinal))
            {
                _session.BackendName = result.BackendName;
                _session.ProcessId = result.ProcessId;
                _status.ForeColor = Color.DarkGreen;
                _status.Text = "Kanal hüppas teise serverisse: " + result.BackendName + " (pid " + result.ProcessId + ").";
            }
        }

        private async Task DiagnoseAsync()
        {
            var address = _address.Text.Trim();
            Log("Diagnostika: teen sama kätluse käsitsi (ilma WCF-ita), et näha päris HTTP staatust.");
            var result = await Task.Run(() => ClientDiagnostics.Run(address, _authCert));

            Log(result.Detail.TrimEnd());
            Log("VERDIKT" + Environment.NewLine + result.Verdict);
            Log("Kliendi logi: " + ClientDiagnostics.LogPath + Environment.NewLine +
                "Serveri koondraport (käivita IIS masinas): powershell -File scripts\\Get-EidReport.ps1");

            _status.ForeColor = Color.Firebrick;
            _status.Text = result.Verdict;
        }

        private static bool LooksLikeCertificateProblem(Exception ex)
        {
            var flat = Flatten(ex);
            return flat.IndexOf("403", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   flat.IndexOf("Forbidden", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   flat.IndexOf("Anonymous", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   flat.IndexOf("trust relationship", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   flat.IndexOf("SSL/TLS", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private async Task<T> CallAsync<T>(Func<IDemoService, T> call)
        {
            var address = _address.Text.Trim();
            Exception last = null;

            for (var attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    if (_channel == null)
                        _channel = DemoChannel.Open(address, _authCert, keepAlive: true);
                    return await Task.Run(() => call(_channel));
                }
                catch (Exception ex)
                {
                    last = ex;
                    DemoChannel.Close(_channel);
                    _channel = null;
                    DemoChannel.DropPooledConnections(address);
                    if (attempt < 2 && CanFailover(ex))
                    {
                        Log("Kanal katkes. Ootan hetke ja avan uue TCP/TLS teise backend'i poole.");
                        await Task.Delay(400);
                        continue;
                    }
                    throw;
                }
            }

            throw last;
        }

        private static bool CanFailover(Exception ex)
        {
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (e is FaultException)
                    return false;
                if (e is CommunicationException || e is TimeoutException || e is SocketException || e is IOException)
                    return true;
                var msg = e.Message ?? "";
                if (msg.IndexOf("aborted", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    msg.IndexOf("underlying connection was closed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    msg.IndexOf("HTTP.SYS", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        private void ResetSession()
        {
            DemoChannel.Close(_channel);
            _channel = null;
            _session = null;
            _ping.Enabled = false;
            _sign.Enabled = false;
            _signText.Enabled = false;
            _signResult.Text = "";
            _status.ForeColor = SystemColors.ControlText;
        }

        private void Log(string line)
        {
            _log.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + line + Environment.NewLine + Environment.NewLine);
            ClientDiagnostics.Log(line.Replace(Environment.NewLine, " | "));
        }

        private static string Explain(Exception ex)
        {
            var flat = Flatten(ex);
            if (flat.IndexOf("403", StringComparison.OrdinalIgnoreCase) >= 0 ||
                flat.IndexOf("Forbidden", StringComparison.OrdinalIgnoreCase) >= 0 ||
                flat.IndexOf("Anonymous", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Server vastas 403. WCF ei näita alamstaatust, seega päris põhjus on üks kolmest: " +
                       "403.7 (serti ei küsitud), 403.16 (ahel ei ole usaldatud) või 403.13 (tühistus/OCSP). " +
                       "Diagnostika käivitub automaatselt ja ütleb, kumb neist see oli." +
                       Environment.NewLine + flat;
            }
            return flat;
        }

        private static string Flatten(Exception ex)
        {
            var sb = new StringBuilder();
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (sb.Length > 0) sb.Append(" -> ");
                sb.Append(e.Message);
            }
            return sb.ToString();
        }

        private static string NewCorrelation() => Guid.NewGuid().ToString("N").Substring(0, 8);
    }
}
