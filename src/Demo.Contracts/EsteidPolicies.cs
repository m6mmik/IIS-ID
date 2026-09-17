using System.Collections.Generic;

namespace Demo.Contracts
{
    public static class EsteidPolicies
    {
        public const string NcpPlus = "0.4.0.2042.1.2";
        public const string AnyPolicy = "2.5.29.32.0";
        public const string ClientAuthEku = "1.3.6.1.5.5.7.3.2";

        public static readonly HashSet<string> Esteid2018Documents = new HashSet<string>
        {
            "1.3.6.1.4.1.51361.1.1.1",
            "1.3.6.1.4.1.51361.1.1.2",
            "1.3.6.1.4.1.51361.1.1.3",
            "1.3.6.1.4.1.51361.1.1.4",
            "1.3.6.1.4.1.51361.1.1.5",
            "1.3.6.1.4.1.51361.1.1.6",
            "1.3.6.1.4.1.51361.1.1.7",
            "1.3.6.1.4.1.51455.1.1.1"
        };

        public static readonly HashSet<string> Esteid2025Documents = new HashSet<string>
        {
            "1.3.6.1.4.1.51361.2.1.1",
            "1.3.6.1.4.1.51361.2.1.2",
            "1.3.6.1.4.1.51361.2.1.3",
            "1.3.6.1.4.1.51361.2.1.4",
            "1.3.6.1.4.1.51361.2.1.5",
            "1.3.6.1.4.1.51361.2.1.6",
            "1.3.6.1.4.1.51455.2.1.1"
        };
    }
}
