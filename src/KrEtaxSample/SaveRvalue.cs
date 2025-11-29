using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace KrEtaxSample;

/// <summary>
/// C# port of com.barostudio.SaveRvalue.
/// </summary>
public static class SaveRvalue
{
    /// <summary>
    /// Mirrors SaveRvalue.main in SaveRvalue.java.
    /// </summary>
    public static byte[] ExtractRvalue(string p12Path, string password)
    {
        using var stream = File.OpenRead(p12Path);
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(stream, password.ToCharArray());

        foreach (string alias in store.Aliases)
        {
            if (!store.IsKeyEntry(alias))
            {
                continue;
            }

            var keyEntry = store.GetKey(alias);

            // Attempt to mirror the attribute walk in SaveRvalue.unwrapXXKey.
            foreach (DerObjectIdentifier oid in keyEntry.BagAttributeKeys)
            {
                var value = keyEntry[oid];
                if (value is DerBitString bitString)
                {
                    return bitString.GetBytes();
                }

                if (value is Asn1OctetString octetString && octetString.GetOctets().Length > 0)
                {
                    // Some toolkits wrap the r-value as an octet string; preserve it if found.
                    return octetString.GetOctets();
                }
            }

            var pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyEntry.Key);
            var attributes = pkInfo.Attributes;
            if (attributes != null && attributes.Count > 0)
            {
                var attribute = AttributePkcs.GetInstance(attributes[0]);
                if (attribute.AttrValues.Count > 0)
                {
                    var attrValue = attribute.AttrValues[0];
                    if (attrValue is DerBitString bitFromPkInfo)
                    {
                        return bitFromPkInfo.GetBytes();
                    }
                }
            }
        }

        throw new InvalidOperationException("Unable to locate signer r-value inside PKCS#12 bag");
    }
}
