using System.Reflection;
using Newtonsoft.Json;

namespace Fido2Demo
{ 
    public class ClientDataJson
    {
        public string Type { get; set; }

        public string Challenge { get; set; }

        public string Origin { get; set; }

        public string CrossOrigin { get; set; }
    }

    public class CredPublicKey
    {
        public CredPublicKey(List<KeyValuePair<string, object>> publicKeyValues) // Use of Reflection here
        {
            foreach (var prop in typeof(CredPublicKey).GetProperties())
            {
                var propName =
                    (prop.GetCustomAttributes(typeof(JsonPropertyAttribute)).First() as JsonPropertyAttribute)
                    ?.PropertyName;

                var value = publicKeyValues.FirstOrDefault(x => x.Key.Equals(propName)).Value;

                prop.SetValue(this, value, null);
            }
        }

        [JsonProperty("1")] public object KeyType { get; set; }

        [JsonProperty("3")] public object Algorithm { get; set; }

        [JsonProperty("-1")] public object Curve { get; set; }

        [JsonProperty("-2")] public object X { get; set; }

        [JsonProperty("-3")] public object Y { get; set; }
    }

    public class AttestationObject
    {
        public AttestationObject(List<KeyValuePair<string, object>> attestationObjectValues) // Use of Reflection here
        {
            foreach (var prop in typeof(AttestationObject).GetProperties())
            {
                var propName =
                    (prop.GetCustomAttributes(typeof(JsonPropertyAttribute)).First() as JsonPropertyAttribute)
                    ?.PropertyName;

                var value = attestationObjectValues.FirstOrDefault(x => x.Key.Equals(propName)).Value;

                prop.SetValue(this, value, null);
            }
        }

        //Format
        [JsonProperty("fmt")] public object Fmt { get; set; }

        //AttestationObject
        [JsonProperty("attStmt")] public object AttStmt { get; set; }

        [JsonProperty("authData")] public object AuthData { get; set; }

        [JsonProperty("decodedAuthData")] public object DecodedAuthData { get; set; }
    }
}
