using System.Runtime.Serialization;
using System.ServiceModel;

namespace Demo.Contracts
{
    [ServiceContract(Namespace = "https://iis-id.local/demo")]
    public interface IDemoService
    {
        [OperationContract]
        WhoAmIResponse WhoAmI(WhoAmIRequest request);

        [OperationContract]
        PingResponse Ping(PingRequest request);

        [OperationContract]
        SignVerifyResponse SubmitSignature(SignRequest request);
    }

    [DataContract]
    public class WhoAmIRequest
    {
        [DataMember] public string CorrelationId { get; set; }
    }

    [DataContract]
    public class WhoAmIResponse
    {
        [DataMember] public string CorrelationId { get; set; }
        [DataMember] public string BackendName { get; set; }
        [DataMember] public string AppPool { get; set; }
        [DataMember] public int ProcessId { get; set; }
        [DataMember] public string AuthCertSubject { get; set; }
        [DataMember] public string AuthCertIssuer { get; set; }
        [DataMember] public string AuthCertSerial { get; set; }
        [DataMember] public string PersonalCode { get; set; }
        [DataMember] public string[] CertificatePolicies { get; set; }
        [DataMember] public bool PolicyAccepted { get; set; }
        [DataMember] public string PolicyReason { get; set; }
        [DataMember] public string ServerTimeUtc { get; set; }
    }

    [DataContract]
    public class PingRequest
    {
        [DataMember] public string CorrelationId { get; set; }
        [DataMember] public string Message { get; set; }
    }

    [DataContract]
    public class PingResponse
    {
        [DataMember] public string CorrelationId { get; set; }
        [DataMember] public string Echo { get; set; }
        [DataMember] public string BackendName { get; set; }
        [DataMember] public string AppPool { get; set; }
        [DataMember] public int ProcessId { get; set; }
        [DataMember] public string PersonalCode { get; set; }
        [DataMember] public string ServerTimeUtc { get; set; }
    }

    [DataContract]
    public class SignRequest
    {
        [DataMember] public string CorrelationId { get; set; }
        [DataMember] public string DataUtf8 { get; set; }
        [DataMember] public byte[] Signature { get; set; }
        [DataMember] public byte[] SigningCertificateDer { get; set; }
        [DataMember] public string HashAlgorithm { get; set; }
    }

    [DataContract]
    public class SignVerifyResponse
    {
        [DataMember] public string CorrelationId { get; set; }
        [DataMember] public string BackendName { get; set; }
        [DataMember] public int ProcessId { get; set; }
        [DataMember] public bool SignatureValid { get; set; }
        [DataMember] public bool SamePersonAsAuthCert { get; set; }
        [DataMember] public string SigningCertSubject { get; set; }
        [DataMember] public string AuthPersonalCode { get; set; }
        [DataMember] public string SignPersonalCode { get; set; }
        [DataMember] public string Message { get; set; }
    }
}
