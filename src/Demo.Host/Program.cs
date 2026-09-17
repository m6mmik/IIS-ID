using System;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using Demo.Contracts;
using Demo.Service;

namespace Demo.Host
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            var name = Read(args, "--name") ?? "Backend1";
            var httpsPort = int.Parse(Read(args, "--https") ?? "8443");
            var httpPort = int.Parse(Read(args, "--http") ?? "8080");
            var bind = Read(args, "--bind") ?? "127.0.0.1";
            if (bind == "0.0.0.0" || bind == "*")
                bind = "+";
            Environment.SetEnvironmentVariable("DEMO_BACKEND", name);
            Environment.SetEnvironmentVariable("APP_POOL_ID", name + "Pool");
            Environment.SetEnvironmentVariable("DEMO_HEALTH_BIND", bind);

            var httpsBase = new Uri("https://" + bind + ":" + httpsPort + "/");
            var host = new ServiceHost(typeof(DemoService), httpsBase);

            var binding = DemoBinding();
            host.AddServiceEndpoint(typeof(IDemoService), binding, "Demo.svc");
            host.Description.Behaviors.Find<ServiceDebugBehavior>().IncludeExceptionDetailInFaults = true;
            var metadata = host.Description.Behaviors.Find<ServiceMetadataBehavior>();
            if (metadata == null)
            {
                metadata = new ServiceMetadataBehavior();
                host.Description.Behaviors.Add(metadata);
            }
            host.Credentials.ClientCertificate.Authentication.CertificateValidationMode =
                X509CertificateValidationMode.PeerOrChainTrust;
            host.Credentials.ClientCertificate.Authentication.RevocationMode =
                System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;

            var health = StartHealth(httpPort, name);
            host.Open();
            Console.WriteLine("{0}  WCF https://{1}:{2}/Demo.svc  health http://{1}:{3}/health.json  pid={4}",
                name, bind, httpsPort, httpPort, System.Diagnostics.Process.GetCurrentProcess().Id);
            Console.WriteLine("Ctrl+C peata.");
            var done = new ManualResetEvent(false);
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.Set(); };
            done.WaitOne();
            host.Close();
            health.Stop();
            return 0;
        }

        private static WSHttpBinding DemoBinding()
        {
            var binding = new WSHttpBinding(SecurityMode.Transport);
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
            return binding;
        }

        private static HttpListener StartHealth(int port, string name)
        {
            var bind = Environment.GetEnvironmentVariable("DEMO_HEALTH_BIND") ?? "127.0.0.1";
            var listener = new HttpListener();
            listener.Prefixes.Add("http://" + bind + ":" + port + "/");
            listener.Start();
            listener.BeginGetContext(ar => HealthCallback(ar, listener, name), null);
            return listener;
        }

        private static void HealthCallback(IAsyncResult ar, HttpListener listener, string name)
        {
            if (!listener.IsListening)
                return;
            HttpListenerContext ctx;
            try { ctx = listener.EndGetContext(ar); }
            catch { return; }

            try
            {
                listener.BeginGetContext(x => HealthCallback(x, listener, name), null);
                if (ctx.Request.Url.AbsolutePath.IndexOf("health", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    ctx.Response.StatusCode = 404;
                    ctx.Response.Close();
                    return;
                }

                var json = "{\"status\":\"ok\",\"site\":\"" + name + "\",\"pid\":" +
                           System.Diagnostics.Process.GetCurrentProcess().Id + "}";
                var bytes = Encoding.UTF8.GetBytes(json);
                ctx.Response.ContentType = "application/json";
                ctx.Response.StatusCode = 200;
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
                ctx.Response.Close();
            }
            catch (Exception)
            {
                try { ctx.Response.Abort(); } catch { }
            }
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
