using System.Collections;
using System.Text;
using Fido2NetLib.Cbor;
using NuGet.Protocol;

namespace Fido2Demo;

public class Decoder
{
    public static object GetDecodedAuthenticatorData(byte[] authenticatorData)
    {
        try
        {
           var span = authenticatorData.AsSpan();

            // RP ID Hash (32 bytes)
            var rpIdHash = span.Slice(0, 32);
            span = span.Slice(32);

            // Flags (1 byte)
            var flagsBuf = span.Slice(0, 1).ToArray();
            var flags = new BitArray(flagsBuf);
            span = span.Slice(1);
            var userPresent = flags[0]; // (UP)

            // Bit 1 reserved for future use (RFU1)
            var userVerified = flags[2]; // (UV)

            // Bits 3-5 reserved for future use (RFU2)
            var attestedCredentialData = flags[6]; // (AT)
            var extensionDataIncluded = flags[7]; // (ED)

            // Signature counter
            var counterBuf = span.Slice(0, 4);
            span = span.Slice(4);
            var counter = BitConverter.ToUInt32(counterBuf);

            return new
            {
                rpIdHash = rpIdHash.ToArray(),
                flags = new { userVerified, userPresent, attestedCredentialData, extensionDataIncluded },
                counter
            };
        }
        catch (Exception e)
        {
            return $"Could not decode: {e}";
        }
    }

    public static object GetDecodedAttestationObject(object authData)
    {
        var span = (authData as byte[]).AsSpan();
        
        var rpIdHash = span.Slice(0, 32); 
        span = span.Slice(32);
        
        var flags = new BitArray(span.Slice(0, 1).ToArray()); 
        span = span.Slice(1);

        var counterBuf = span.Slice(0, 4); 
        span = span.Slice(4);
        
        var counter = BitConverter.ToUInt32(counterBuf);
        
        // cred data - AAGUID (16 bytes)
        var aaguid = span.Slice(0, 16); 
        span = span.Slice(16);
        
        // cred data - L (2 bytes, big-endian uint16)
        var credIdLenBuf = span.Slice(0, 2); 
        span = span.Slice(2);
        credIdLenBuf.Reverse();
        var credentialIdLength = BitConverter.ToUInt16(credIdLenBuf);

        // cred data - Credential ID (L bytes)
        var credentialId = span.Slice(0, credentialIdLength);
        span = span.Slice(credentialIdLength);

        var coseStruct = CborObject.Decode(span.ToArray());
        var keyValues = GetCborValues(((CborMap)coseStruct).ToList());
        var key = new CredPublicKey(keyValues);        
        
        return new
        {
            rpIdHash = rpIdHash.ToArray(),
            flags = new
            {
                userPresent = flags[0],
                userVerified = flags[2],
                attestedCredentialData = flags[6],
                extensionDataIncluded = flags[7],
            },
            counter,
            credentialId = credentialId.ToArray(),
            aaguid = Guid.Parse(BitConverter.ToString(aaguid.ToArray()).Replace("-", string.Empty)),
            key
        };
    }

    public static object GetClientDataJson(byte[] credentialAttestationClientDataJson)
    {
        try
        {
            return Encoding.Default.GetString(credentialAttestationClientDataJson).FromJson<ClientDataJson>();
        }
        catch (Exception e)
        {
            return $"Could not decode {e.Message}";
        }
    }

    public static List<KeyValuePair<string, object>> GetCborDecodedObject(byte[] data)
    {
        List<KeyValuePair<string, object>> decodedItems = new List<KeyValuePair<string, object>>();
        
        try
        {
            var items = ((CborMap)CborObject.Decode(data)).ToList();
            decodedItems = GetCborValues(items);
        }
        catch (Exception e)
        {
            decodedItems.Add(new("Exception", $"Could not decode: {e.Message}"));
        }
        
        return decodedItems;
    }

    public static List<KeyValuePair<string, object>> GetCborValues(List<KeyValuePair<CborObject, CborObject>> items)
    {
        List<KeyValuePair<string, object>> decodedItems = new List<KeyValuePair<string, object>>();

        foreach (var item in items)
        {
            string itemKey = null;
            object itemValue = GetCborItemValue(item.Value);

            if (item.Key as CborTextString != null)
                itemKey = ((CborTextString)item.Key).Value;
            else if (item.Key as CborInteger != null)
                itemKey = ((CborInteger)item.Key).Value.ToString();

            decodedItems.Add(new(itemKey, itemValue));
        }

        return decodedItems;
    }

    public static object GetCborItemValue(CborObject itemValue)
    {
        if (itemValue as CborInteger != null)
            return ((CborInteger)itemValue).Value;
        
        if (itemValue as CborTextString != null)
            return ((CborTextString)itemValue).Value;
        
        if (itemValue as CborByteString != null)
            return ((CborByteString)itemValue).Value;

        return itemValue;
    }

}
