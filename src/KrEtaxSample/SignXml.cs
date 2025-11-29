using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace KrEtaxSample;

/// <summary>
/// C# port of com.barostudio.SignXML.
/// </summary>
public static class SignXml
{
    /// <summary>
    /// Mirrors SignXML.loadPrivateKeyAndCertificates in SignXML.java.
    /// </summary>
    public static X509Certificate2 LoadPrivateKeyAndCertificate(string p12Path, string password)
    {
        return new X509Certificate2(p12Path, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
    }

    /// <summary>
    /// Mirrors SignXML.sign in SignXML.java.
    /// </summary>
    public static void Sign(X509Certificate2 certificate, Stream inputXml, Stream outputXml)
    {
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa == null)
        {
            throw new InvalidOperationException("Certificate does not contain an RSA private key");
        }

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(inputXml);

        var signedXml = new SignedXml(doc)
        {
            SigningKey = rsa
        };

        var reference = new Reference(string.Empty)
        {
            DigestMethod = SignedXml.XmlDsigSHA256Url
        };

        reference.AddTransform(new XmlDsigExcC14NTransform(false));

        var xpathTransform = new XmlDsigXPathTransform();
        var xpathDoc = new XmlDocument();
        var xpathEl = xpathDoc.CreateElement("ds", "XPath", SignedXml.XmlDsigNamespaceUrl);
        xpathEl.InnerText = "not(self::*[name() = 'TaxInvoice'] | ancestor-or-self::*[name() = 'ExchangedDocument'] | ancestor-or-self::ds:Signature)";
        xpathDoc.AppendChild(xpathEl);
        xpathTransform.LoadInnerXml(xpathDoc.ChildNodes);
        reference.AddTransform(xpathTransform);

        signedXml.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        var xmlDigitalSignature = signedXml.GetXml();

        var nsManager = new XmlNamespaceManager(doc.NameTable);
        nsManager.AddNamespace("tax", "urn:kr:or:kec:standard:Tax:ReusableAggregateBusinessInformationEntitySchemaModule:1:0");
        var pivot = doc.SelectSingleNode("//tax:TaxInvoiceDocument", nsManager);
        if (pivot?.ParentNode == null)
        {
            throw new InvalidOperationException("Could not locate TaxInvoiceDocument element to insert signature");
        }

        var imported = doc.ImportNode(xmlDigitalSignature, true);
        pivot.ParentNode.InsertBefore(imported, pivot);

        using var writer = XmlWriter.Create(outputXml, new XmlWriterSettings
        {
            Encoding = new System.Text.UTF8Encoding(false),
            Indent = true,
            OmitXmlDeclaration = false
        });
        doc.Save(writer);
    }
}
