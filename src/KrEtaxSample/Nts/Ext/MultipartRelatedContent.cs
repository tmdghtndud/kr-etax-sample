using System.Net.Http.Headers;
using System.Net.Http;
using System.Text;

namespace KrEtaxSample.Nts.Ext;

/// <summary>
/// Multipart formatter that mirrors MultipartRelatedEntity in Java.
/// </summary>
public class MultipartRelatedContent : MultipartContent
{
    /// <summary>
    /// Corresponds to the overridden generateContentType in MultipartRelatedEntity.java.
    /// </summary>
    public MultipartRelatedContent(string boundary)
        : base("related", boundary)
    {
        Headers.ContentType = new MediaTypeHeaderValue("multipart/related");
        Headers.ContentType.Parameters.Add(new NameValueHeaderValue("type", "\"text/xml\""));
        Headers.ContentType.Parameters.Add(new NameValueHeaderValue("start", "\"<SOAPPart>\""));
        Headers.ContentType.Parameters.Add(new NameValueHeaderValue("boundary", $"\"{boundary}\""));
    }
}
