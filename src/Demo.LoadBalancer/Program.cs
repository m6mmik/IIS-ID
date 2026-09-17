using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Demo.LoadBalancer
{
    internal static class Program
    {
        private static Backend[] Backends;
        private static int _rr;
        private static string _mode = "roundrobin";
        private static IPAddress _bind = IPAddress.Loopback;
        private static string _labScript;
        private static string _lastAction;

        private static int Main(string[] args)
        {
            Backends = LoadBackends(args);
            _bind = ParseBind(ReadArg(args, "--bind") ?? "127.0.0.1");
            _labScript = ReadArg(args, "--lab") ?? FindLabScript();
            var listenPort = ReadArg(args, "--listen") ?? "9443";
            var statsPort = ReadArg(args, "--stats") ?? "8404";
            _mode = (ReadArg(args, "--balance") ?? "roundrobin").ToLowerInvariant();

            ServicePointManager.Expect100Continue = false;
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("TCP passthrough load balancer (HAProxy analoog)");
            Console.WriteLine("listen={0}:{1}  stats=http://127.0.0.1:{2}/  balance={3}",
                _bind, listenPort, statsPort, _mode);
            foreach (var b in Backends)
                Console.WriteLine("  {0}  {1}:{2}  health :{3}", b.Name, b.Host, b.Port, b.HealthPort);
            Console.WriteLine("lab.ps1={0}", string.IsNullOrEmpty(_labScript) ? "(puudub — Kinni/Käima ei tööta)" : _labScript);
            Console.WriteLine("Ctrl+C peata.");

            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            Task.Run(() => HealthLoop(cts.Token));
            Task.Run(() => StatsLoop(int.Parse(statsPort), cts.Token));
            ListenLoop(int.Parse(listenPort), cts.Token).GetAwaiter().GetResult();
            return 0;
        }

        private static async Task ListenLoop(int port, CancellationToken token)
        {
            var listener = new TcpListener(_bind, port);
            listener.Start();
            using (token.Register(() => listener.Stop()))
            {
                while (!token.IsCancellationRequested)
                {
                    TcpClient client;
                    try { client = await listener.AcceptTcpClientAsync(); }
                    catch (ObjectDisposedException) { break; }

                    var ignored = Task.Run(() => HandleClient(client, token), token);
                }
            }
        }

        private static async Task HandleClient(TcpClient client, CancellationToken token)
        {
            Backend backend = null;
            TcpClient upstream = null;
            var skipped = new List<string>();
            try
            {
                while (upstream == null)
                {
                    backend = PickBackend(client, skipped);
                    if (backend == null)
                    {
                        client.Close();
                        return;
                    }

                    var candidate = new TcpClient();
                    try
                    {
                        if (!await Check(backend))
                        {
                            backend.Healthy = false;
                            skipped.Add(backend.Name);
                            try { candidate.Close(); } catch { }
                            Console.WriteLine("{0} health DOWN, ei suuna HTTP.sys kummitusele.", backend.Name);
                            continue;
                        }

                        var connect = candidate.ConnectAsync(backend.Host, backend.Port);
                        var completed = await Task.WhenAny(connect, Task.Delay(TimeSpan.FromSeconds(2), token));
                        if (completed != connect)
                            throw new TimeoutException("Backend " + backend.Name + " ei vasta.");
                        await connect;
                        upstream = candidate;
                    }
                    catch (Exception ex)
                    {
                        try { candidate.Close(); } catch { }
                        backend.Healthy = false;
                        skipped.Add(backend.Name);
                        Console.WriteLine("{0} ei avanenud ({1}), proovin teist.", backend.Name, ex.Message);
                    }
                }

                Interlocked.Increment(ref backend.Active);
                Interlocked.Increment(ref backend.Total);
                Console.WriteLine("{0:HH:mm:ss.fff}  {1}:{2} -> {3}:{4} ({5})",
                    DateTime.Now,
                    ((IPEndPoint)client.Client.RemoteEndPoint).Address,
                    ((IPEndPoint)client.Client.RemoteEndPoint).Port,
                    backend.Name, backend.Port,
                    backend.Healthy ? "healthy" : "forced");

                client.NoDelay = true;
                upstream.NoDelay = true;
                var a = Pump(client.GetStream(), upstream.GetStream(), token);
                var b = Pump(upstream.GetStream(), client.GetStream(), token);
                await Task.WhenAny(a, b);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ühendus katkes: {0}", ex.Message);
            }
            finally
            {
                if (backend != null && upstream != null)
                    Interlocked.Decrement(ref backend.Active);
                try { client.Close(); } catch { }
                try { if (upstream != null) upstream.Close(); } catch { }
            }
        }

        private static async Task Pump(NetworkStream from, NetworkStream to, CancellationToken token)
        {
            var buffer = new byte[16 * 1024];
            while (!token.IsCancellationRequested)
            {
                var n = await from.ReadAsync(buffer, 0, buffer.Length, token);
                if (n <= 0)
                    break;
                await to.WriteAsync(buffer, 0, n, token);
            }
        }

        private static Backend PickBackend(TcpClient client, ICollection<string> skipped)
        {
            var live = Backends.Where(b => b.Healthy && !b.Draining && !skipped.Contains(b.Name)).ToArray();
            if (live.Length == 0)
                return null;

            if (_mode == "source")
            {
                var ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                var hash = Math.Abs(ip.GetHashCode());
                return live[hash % live.Length];
            }

            var i = Interlocked.Increment(ref _rr);
            return live[Math.Abs(i) % live.Length];
        }

        private static async Task HealthLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                foreach (var backend in Backends)
                {
                    var ok = await Check(backend);
                    if (ok != backend.Healthy)
                        Console.WriteLine("{0} health -> {1}", backend.Name, ok ? "UP" : "DOWN");
                    backend.Healthy = ok;
                }
                try { await Task.Delay(TimeSpan.FromSeconds(2), token); }
                catch (TaskCanceledException) { break; }
            }
        }

        private static async Task<bool> Check(Backend backend)
        {
            try
            {
                var url = "http://" + backend.Host + ":" + backend.HealthPort + "/health.json";
                var request = (HttpWebRequest)WebRequest.Create(url);
                request.Timeout = 1500;
                request.ReadWriteTimeout = 1500;
                request.Method = "GET";
                using (var response = (HttpWebResponse)await request.GetResponseAsync())
                    return (int)response.StatusCode == 200;
            }
            catch
            {
                return false;
            }
        }

        private static async Task StatsLoop(int port, CancellationToken token)
        {
            var listener = new HttpListener();
            listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
            listener.Start();
            using (token.Register(listener.Stop))
            {
                while (!token.IsCancellationRequested)
                {
                    HttpListenerContext ctx;
                    try { ctx = await listener.GetContextAsync(); }
                    catch { break; }

                    var path = ctx.Request.Url.AbsolutePath.Trim('/');
                    var action = HandleStatsAction(path);
                    if (action)
                    {
                        ctx.Response.Redirect("/");
                        ctx.Response.Close();
                        continue;
                    }

                    var html = RenderStats();
                    var bytes = Encoding.UTF8.GetBytes(html);
                    ctx.Response.ContentType = "text/html; charset=utf-8";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
                    ctx.Response.Close();
                }
            }
        }

        private static bool HandleStatsAction(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;
            var slash = path.IndexOf('/');
            var cmd = (slash < 0 ? path : path.Substring(0, slash)).ToLowerInvariant();
            var name = slash < 0 ? "" : path.Substring(slash + 1);
            if (cmd == "balance" && name.Length > 0)
            {
                _mode = name.ToLowerInvariant();
                _lastAction = "balance=" + _mode;
                return true;
            }
            if (name.Length == 0)
                return false;
            if (cmd == "drain")
            {
                SetDrain(name, true);
                _lastAction = name + " drain (protsess jääb käima, uusi ühendusi ei anta)";
                return true;
            }
            if (cmd == "ready")
            {
                SetDrain(name, false);
                _lastAction = name + " ready";
                return true;
            }
            if (cmd == "down" || cmd == "kill")
            {
                SetHealth(name, false);
                _lastAction = RunLab("down", name);
                return true;
            }
            if (cmd == "up" || cmd == "start")
            {
                _lastAction = RunLab("up", name);
                return true;
            }
            return false;
        }

        private static void SetDrain(string name, bool draining)
        {
            var backend = FindBackend(name);
            if (backend == null)
                return;
            backend.Draining = draining;
            Console.WriteLine("{0} draining={1}", backend.Name, draining);
        }

        private static void SetHealth(string name, bool healthy)
        {
            var backend = FindBackend(name);
            if (backend == null)
                return;
            backend.Healthy = healthy;
        }

        private static Backend FindBackend(string name)
        {
            return Backends.FirstOrDefault(b => b.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        }

        private static string RunLab(string command, string target)
        {
            var backend = FindBackend(target);
            var label = backend != null ? backend.Name : target;
            if (string.IsNullOrEmpty(_labScript) || !File.Exists(_labScript))
                return "lab.ps1 puudub. Käivita lab .\\lab.ps1 start kaudu, siis Kinni/Käima töötavad.";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + _labScript + "\" " + command + " " + label,
                    WorkingDirectory = Path.GetDirectoryName(_labScript),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var p = Process.Start(psi))
                {
                    var output = new StringBuilder();
                    p.OutputDataReceived += (_, e) => { if (e.Data != null) output.AppendLine(e.Data); };
                    p.ErrorDataReceived += (_, e) => { if (e.Data != null) output.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    if (!p.WaitForExit(90000))
                    {
                        try { p.Kill(); } catch { }
                        return label + " " + command + " timeout.";
                    }
                    var text = output.ToString().Trim();
                    Console.WriteLine("{0} {1}: {2}", command, label, text.Replace("\r", " ").Replace("\n", " "));
                    if (p.ExitCode != 0)
                        return label + " " + command + " ebaõnnestus: " + (text.Length == 0 ? "exit " + p.ExitCode : text);
                    return label + " " + command + " OK. " + text;
                }
            }
            catch (Exception ex)
            {
                return label + " " + command + " viga: " + ex.Message;
            }
        }

        private static string FindLabScript()
        {
            var dir = AppDomain.CurrentDomain.BaseDirectory;
            for (var i = 0; i < 8 && !string.IsNullOrEmpty(dir); i++)
            {
                var candidate = Path.Combine(dir, "lab.ps1");
                if (File.Exists(candidate))
                    return Path.GetFullPath(candidate);
                dir = Path.GetDirectoryName(dir);
            }
            return null;
        }

        private static string RenderStats()
        {
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=et><head><meta charset=utf-8>");
            sb.Append("<meta http-equiv=refresh content=3>");
            sb.Append("<title>IIS-ID LB</title>");
            sb.Append("<style>");
            sb.Append("body{font-family:'Segoe UI',sans-serif;margin:24px;color:#222}");
            sb.Append("table{border-collapse:collapse} td,th{border:1px solid #ccc;padding:8px 12px}");
            sb.Append(".up{color:#1e8449;font-weight:700} .down{color:#c0392b;font-weight:700}");
            sb.Append("a.btn{display:inline-block;padding:8px 14px;margin:0 4px 0 0;color:#fff;text-decoration:none;border-radius:4px}");
            sb.Append("a.kill{background:#c0392b} a.upbtn{background:#1e8449} a.quiet{background:#7f8c8d}");
            sb.Append(".msg{background:#eef6ff;border:1px solid #bcd;padding:10px 12px}");
            sb.Append("</style></head><body>");
            sb.Append("<h2>TCP passthrough — lab juhtimine</h2>");
            sb.Append("<p>balance=").Append(_mode).Append(" · ");
            sb.Append("<a href='/balance/roundrobin'>roundrobin</a> · ");
            sb.Append("<a href='/balance/source'>source</a></p>");
            if (!string.IsNullOrEmpty(_lastAction))
                sb.Append("<p class=msg>").Append(WebUtility.HtmlEncode(_lastAction)).Append("</p>");
            sb.Append("<table><tr><th>Backend</th><th>TCP</th><th>Health</th><th>State</th><th>Active</th><th>Total</th><th>Failover test</th></tr>");
            foreach (var b in Backends)
            {
                sb.Append("<tr><td>").Append(b.Name).Append("</td>");
                sb.Append("<td>").Append(b.Host).Append(':').Append(b.Port).Append("</td>");
                sb.Append("<td class=").Append(b.Healthy ? "up" : "down").Append('>').Append(b.Healthy ? "UP" : "DOWN").Append("</td>");
                sb.Append("<td>").Append(b.Draining ? "drain" : "ready").Append("</td>");
                sb.Append("<td>").Append(b.Active).Append("</td>");
                sb.Append("<td>").Append(b.Total).Append("</td>");
                sb.Append("<td>");
                sb.Append("<a class='btn kill' href='/down/").Append(b.Name).Append("'>Kinni</a>");
                sb.Append("<a class='btn upbtn' href='/up/").Append(b.Name).Append("'>Käima</a>");
                sb.Append("<a class='btn quiet' href='/drain/").Append(b.Name).Append("'>drain</a>");
                sb.Append("<a class='btn quiet' href='/ready/").Append(b.Name).Append("'>ready</a>");
                sb.Append("</td></tr>");
            }
            sb.Append("</table>");
            sb.Append("<p><b>Kinni</b> tapab IIS-i (nagu VM kinni). Klient peab järgmisel päringul hüppama teise peale. ");
            sb.Append("<b>Käima</b> toob sama backend'i tagasi. Drain ei tapa protsessi.</p>");
            sb.Append("<p>Leht uueneb 3 s tagant. Health: HTTP GET /health.json (mitte 443, mitte mTLS).</p>");
            sb.Append("</body></html>");
            return sb.ToString();
        }

        private static string ReadArg(string[] args, string name)
        {
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            }
            return null;
        }

        private static IPAddress ParseBind(string bind)
        {
            if (bind == "*" || bind == "0.0.0.0" || string.Equals(bind, "any", StringComparison.OrdinalIgnoreCase))
                return IPAddress.Any;
            return IPAddress.Parse(bind);
        }

        private static Backend[] LoadBackends(string[] args)
        {
            var list = new List<Backend>();
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], "--backend", StringComparison.OrdinalIgnoreCase))
                    list.Add(ParseBackend(args[i + 1]));
            }

            var explicitFile = ReadArg(args, "--backends");
            string file = explicitFile;
            if (string.IsNullOrEmpty(file) && list.Count == 0)
                file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "backends.txt");

            if (!string.IsNullOrEmpty(explicitFile) && !File.Exists(explicitFile))
                throw new FileNotFoundException("backends.txt puudub: " + explicitFile);

            if (!string.IsNullOrEmpty(file) && File.Exists(file))
            {
                foreach (var line in File.ReadAllLines(file))
                {
                    var trimmed = line.Trim();
                    if (trimmed.Length == 0 || trimmed[0] == '#')
                        continue;
                    list.Add(ParseBackend(trimmed));
                }
            }

            if (list.Count == 0)
            {
                list.Add(new Backend("Backend1", "127.0.0.1", 8443, 8080));
                list.Add(new Backend("Backend2", "127.0.0.1", 8444, 8081));
            }

            return list.ToArray();
        }

        private static Backend ParseBackend(string spec)
        {
            var normalized = spec.Replace('=', ' ').Replace(',', ' ').Replace(':', ' ');
            var parts = normalized.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                throw new ArgumentException("Backend: Name host httpsPort healthPort  (nt Backend1 10.0.0.11 443 8080)");
            return new Backend(parts[0], parts[1], int.Parse(parts[2]), int.Parse(parts[3]));
        }

        private sealed class Backend
        {
            public Backend(string name, string host, int port, int healthPort)
            {
                Name = name;
                Host = host;
                Port = port;
                HealthPort = healthPort;
            }

            public string Name;
            public string Host;
            public int Port;
            public int HealthPort;
            public bool Healthy;
            public bool Draining;
            public int Active;
            public int Total;
        }
    }
}
