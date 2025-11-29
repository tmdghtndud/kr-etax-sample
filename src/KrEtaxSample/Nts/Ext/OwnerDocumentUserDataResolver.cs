using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace KrEtaxSample.Nts.Ext;

/// <summary>
/// Resolver that mimics ResolverOwnerDocumentUserData in Java.
/// </summary>
public class OwnerDocumentUserDataResolver : XmlResolver
{
    private readonly IDictionary<string, byte[]> _inlineData;

    /// <summary>
    /// Corresponds to the constructor and engineCanResolve logic in ResolverOwnerDocumentUserData.java.
    /// </summary>
    public OwnerDocumentUserDataResolver(IDictionary<string, byte[]> inlineData)
    {
        _inlineData = inlineData;
    }

    public override ICredentials? Credentials { set { } }

    /// <summary>
    /// Returns in-memory attachment bytes similar to engineResolve in the Java resolver.
    /// </summary>
    public override object GetEntity(Uri absoluteUri, string? role, Type? ofObjectToReturn)
    {
        if (_inlineData.TryGetValue(absoluteUri.OriginalString, out var bytes))
        {
            return new MemoryStream(bytes);
        }

        throw new XmlException($"Unable to resolve URI {absoluteUri}");
    }

    /// <summary>
    /// Helper to build a resolver that matches cid:* references.
    /// </summary>
    public static OwnerDocumentUserDataResolver ForCidReference(string cid, byte[] payload)
    {
        return new OwnerDocumentUserDataResolver(new Dictionary<string, byte[]>
        {
            [cid] = payload
        });
    }
}
