using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using KrEtaxSample.Nts.Ext;

namespace KrEtaxSample;

/// <summary>
/// C# port of com.barostudio.SubmitWithSOAP.
/// </summary>
public static class SubmitWithSoap
{
    public const string Wssswa = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";

    /// <summary>
    /// Mirrors SubmitWithSOAP.main in SubmitWithSOAP.java (minus console wiring).
    /// </summary>
    public static async Task<HttpResponseMessage> SubmitAsync(string p12Path, string p12Password, string cmsEncryptedFile, string endPoint)
    {
        var certificate = SignXml.LoadPrivateKeyAndCertificate(p12Path, p12Password);
        var taxInvoiceBlob = await File.ReadAllBytesAsync(cmsEncryptedFile);

        var document = BuildMessage(endPoint, certificate);
        SignMessage(document, certificate, taxInvoiceBlob);

        return await SubmitWithSoapMultipart(document, endPoint, taxInvoiceBlob);
    }

    /// <summary>
    /// Mirrors SubmitWithSOAP.buildMessage in SubmitWithSOAP.java.
    /// </summary>
    public static XmlDocument BuildMessage(string endPoint, X509Certificate2 certificate)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        var en = doc.CreateElement("s", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/");
        doc.AppendChild(en);

        var header = doc.CreateElement("s", "Header", en.NamespaceURI);
        en.AppendChild(header);
        var body = doc.CreateElement("s", "Body", en.NamespaceURI);
        en.AppendChild(body);

        var wsaNs = "http://www.w3.org/2005/08/addressing";
        var kecNs = "http://www.kec.or.kr/standard/Tax/";
        var wsseNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        var wsuNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        void AddTextElement(XmlElement parent, string prefix, string localName, string ns, string value)
        {
            var element = doc.CreateElement(prefix, localName, ns);
            element.InnerText = value;
            parent.AppendChild(element);
        }

        AddTextElement(header, "wsa", "MessageID", wsaNs, "20091013112725078-b9127eac9173494dab9ff31f57c84587");
        AddTextElement(header, "wsa", "To", wsaNs, endPoint);
        AddTextElement(header, "wsa", "Action", wsaNs, "http://www.kec.or.kr/standard/Tax/TaxInvoiceSubmit");

        var messageHeader = doc.CreateElement("kec", "MessageHeader", kecNs);
        header.AppendChild(messageHeader);
        AddTextElement(messageHeader, "kec", "Version", kecNs, "3.0");
        var from = doc.CreateElement("kec", "From", kecNs);
        messageHeader.AppendChild(from);
        AddTextElement(from, "kec", "PartyID", kecNs, "2208203228");
        AddTextElement(from, "kec", "PartyName", kecNs, "National IT Industry Promotion Agency");
        var to = doc.CreateElement("kec", "To", kecNs);
        messageHeader.AppendChild(to);
        AddTextElement(to, "kec", "PartyID", kecNs, "9999999999");
        AddTextElement(to, "kec", "PartyName", kecNs, "National Tax Service");
        AddTextElement(messageHeader, "kec", "ReplyTo", kecNs, "http://www.nipa.or.kr/etax/SendResultsService");
        AddTextElement(messageHeader, "kec", "OperationType", kecNs, "01");
        AddTextElement(messageHeader, "kec", "MessageType", kecNs, "01");
        AddTextElement(messageHeader, "kec", "TimeStamp", kecNs, "2009-10-13T14:27:25.109Z");

        var security = doc.CreateElement("wsse", "Security", wsseNs);
        header.AppendChild(security);
        security.SetAttribute("xmlns:wsu", wsuNs);

        var bst = doc.CreateElement("wsse", "BinarySecurityToken", wsseNs);
        bst.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        bst.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#X509v3");
        bst.SetAttribute("wsu:Id", "X509Token");
        bst.InnerText = Convert.ToBase64String(certificate.RawData);
        security.AppendChild(bst);

        var requestMessage = doc.CreateElement("kec", "RequestMessage", kecNs);
        body.AppendChild(requestMessage);
        AddTextElement(requestMessage, "kec", "SubmitID", kecNs, "12345678-20120904-0123456789abcdef0123456789abcdef");
        AddTextElement(requestMessage, "kec", "TotalCount", kecNs, "5");
        AddTextElement(requestMessage, "kec", "ReferenceID", kecNs, "taxInvoicePart");

        return doc;
    }

    /// <summary>
    /// Mirrors SubmitWithSOAP.signMessage in SubmitWithSOAP.java.
    /// </summary>
    public static void SignMessage(XmlDocument document, X509Certificate2 certificate, byte[] taxInvoiceBlob)
    {
        var signedXml = new SignedXml(document)
        {
            SigningKey = certificate.GetRSAPrivateKey(),
            Resolver = OwnerDocumentUserDataResolver.ForCidReference("cid:taxInvoicePart", taxInvoiceBlob)
        };

        var envelopeReference = new Reference(string.Empty)
        {
            DigestMethod = SignedXml.XmlDsigSHA256Url
        };
        envelopeReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        envelopeReference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(envelopeReference);

        var attachmentReference = new Reference("cid:taxInvoicePart")
        {
            DigestMethod = SignedXml.XmlDsigSHA256Url
        };
        var attachmentTransform = new TransformAttachmentContentSignature();
        attachmentReference.AddTransform(attachmentTransform);
        signedXml.AddReference(attachmentReference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        var signatureElement = signedXml.GetXml();

        var nsManager = new XmlNamespaceManager(document.NameTable);
        nsManager.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        var securityNode = document.SelectSingleNode("//wsse:Security", nsManager);
        securityNode?.AppendChild(document.ImportNode(signatureElement, true));
    }

    /// <summary>
    /// Mirrors SubmitWithSOAP.submitWithSOAP in SubmitWithSOAP.java using HttpClient.
    /// </summary>
    private static async Task<HttpResponseMessage> SubmitWithSoapMultipart(XmlDocument document, string endPoint, byte[] taxInvoiceBlob)
    {
        var xmlString = Canonicalize(document);
        var boundary = $"----kr-etax-{Guid.NewGuid():N}";
        var multipart = new MultipartRelatedContent(boundary);

        var soapPart = new StringContent(xmlString, Encoding.UTF8, "text/xml");
        soapPart.Headers.ContentDisposition = new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment")
        {
            Name = "soap-req"
        };
        soapPart.Headers.Add("Content-ID", "<SOAPPart>");
        multipart.Add(soapPart);

        var taxInvoicePart = new ByteArrayContent(taxInvoiceBlob);
        taxInvoicePart.Headers.ContentDisposition = new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment")
        {
            Name = "taxinvoice",
            FileName = "taxinvoice.cms"
        };
        taxInvoicePart.Headers.Add("Content-ID", "<taxInvoicePart>");
        multipart.Add(taxInvoicePart);

        using var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Post, endPoint)
        {
            Content = multipart
        };
        request.Headers.TryAddWithoutValidation("Soapaction", "\"\"");
        request.Headers.TryAddWithoutValidation("Accept", "text/xml, multipart/related, text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2");

        return await client.SendAsync(request);
    }

    /// <summary>
    /// Mirrors SubmitWithSOAP.asString in SubmitWithSOAP.java.
    /// </summary>
    public static string Canonicalize(XmlDocument document)
    {
        using var stream = new MemoryStream();
        document.Save(stream);
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
