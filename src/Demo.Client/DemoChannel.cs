using System;
using System.Collections;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using Demo.Contracts;

namespace Demo.Client
{
    internal static class DemoChannel
    {
        public static IDemoService Open(string address, X509Certificate2 authCert, bool keepAlive)
        {
            if (authCert == null)
                throw new InvalidOperationException("Autentimissertifikaat (PIN1) puudub.");

            RaiseConnectionLimit(address);
            var binding = CreateBinding(keepAlive);
            var endpoint = new EndpointAddress(new Uri(address), EndpointIdentity.CreateDnsIdentity("demo.local"));
            var factory = new ChannelFactory<IDemoService>(binding, endpoint);
            factory.Credentials.ClientCertificate.Certificate = authCert;
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode =
                X509CertificateValidationMode.PeerOrChainTrust;
            factory.Credentials.ServiceCertificate.Authentication.RevocationMode = X509RevocationMode.NoCheck;

            var channel = factory.CreateChannel();
            var client = (IClientChannel)channel;
            client.OperationTimeout = TimeSpan.FromSeconds(20);
            client.AllowInitializationUI = true;
            client.Closed += (_, __) => SafeCloseFactory(factory);
            client.Faulted += (_, __) => SafeCloseFactory(factory);
            return channel;
        }

        public static CustomBinding CreateBinding(bool keepAlive)
        {
            var ws = new WSHttpBinding(SecurityMode.Transport);
            ws.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
            ws.MaxReceivedMessageSize = 4 * 1024 * 1024;
            ws.SendTimeout = TimeSpan.FromSeconds(15);
            ws.OpenTimeout = TimeSpan.FromSeconds(10);
            ws.ReceiveTimeout = TimeSpan.FromSeconds(15);
            ws.CloseTimeout = TimeSpan.FromSeconds(10);

            var elements = ws.CreateBindingElements();
            var transport = elements.Find<HttpsTransportBindingElement>();
            if (transport != null)
                transport.KeepAliveEnabled = keepAlive;

            return new CustomBinding(elements);
        }

        public static void Close(IDemoService channel)
        {
            if (channel == null)
                return;

            var client = (IClientChannel)channel;
            try
            {
                if (client.State != CommunicationState.Opened)
                    client.Abort();
                else
                    client.Close();
            }
            catch
            {
                client.Abort();
            }
        }

        public static void DropPooledConnections(string address)
        {
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12 | (SecurityProtocolType)12288;
                var sp = ServicePointManager.FindServicePoint(new Uri(address));
                var idle = sp.MaxIdleTime;
                sp.MaxIdleTime = 1;
                var field = typeof(ServicePoint).GetField("m_ConnectionGroupList",
                    BindingFlags.Instance | BindingFlags.NonPublic);
                var list = field != null ? field.GetValue(sp) as Hashtable : null;
                if (list != null)
                {
                    foreach (var key in new ArrayList(list.Keys))
                    {
                        if (key != null)
                            sp.CloseConnectionGroup(key.ToString());
                    }
                }
                sp.CloseConnectionGroup(string.Empty);
                sp.ConnectionLimit = Math.Max(sp.ConnectionLimit, 8);
                sp.MaxIdleTime = idle > 1 ? idle : 100000;
            }
            catch
            {
                // ignore
            }
        }

        public static void RaiseConnectionLimit(string address)
        {
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12 | (SecurityProtocolType)12288;
                var sp = ServicePointManager.FindServicePoint(new Uri(address));
                sp.ConnectionLimit = Math.Max(sp.ConnectionLimit, 20);
            }
            catch
            {
                // ignore
            }
        }

        private static void SafeCloseFactory(ChannelFactory factory)
        {
            try
            {
                if (factory.State == CommunicationState.Faulted)
                    factory.Abort();
                else
                    factory.Close();
            }
            catch
            {
                factory.Abort();
            }
        }
    }
}
