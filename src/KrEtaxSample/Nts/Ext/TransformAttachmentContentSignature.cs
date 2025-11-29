using System;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace KrEtaxSample.Nts.Ext;

/// <summary>
/// Transform implementation that mirrors TransformAttachementContentSignature in Java.
/// </summary>
public class TransformAttachmentContentSignature : Transform
{
    public const string ImplementedTransformUri =
        "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";

    private Stream? _inputStream;

    public TransformAttachmentContentSignature()
    {
        Algorithm = ImplementedTransformUri;
    }

    /// <summary>
    /// Mirrors the accepted input types of TransformAttachementContentSignature.java.
    /// </summary>
    public override Type[] InputTypes => new[] { typeof(Stream), typeof(byte[]) };

    /// <summary>
    /// Mirrors the accepted output types of TransformAttachementContentSignature.java.
    /// </summary>
    public override Type[] OutputTypes => new[] { typeof(byte[]), typeof(Stream) };

    /// <summary>
    /// Corresponds to enginePerformTransform in TransformAttachementContentSignature.java.
    /// </summary>
    public override object GetOutput(Type type)
    {
        if (type != typeof(byte[]) && type != typeof(object))
        {
            throw new ArgumentException("type");
        }

        return (byte[])GetOutput();
    }

    /// <summary>
    /// Corresponds to enginePerformTransform returning XMLSignatureInput bytes in Java.
    /// </summary>
    public override object GetOutput()
    {
        if (_inputStream == null)
        {
            throw new InvalidOperationException("Input stream is not set for transform");
        }

        using var ms = new MemoryStream();
        _inputStream.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Mirrors TransformSpi.enginePerformTransform input loading.
    /// </summary>
    public override void LoadInput(object obj)
    {
        _inputStream = obj switch
        {
            Stream stream => stream,
            byte[] data => new MemoryStream(data),
            _ => throw new ArgumentException("Unsupported input type for transform", nameof(obj))
        };
    }

    /// <summary>
    /// No-op load that mirrors the Java behavior.
    /// </summary>
    public override void LoadInnerXml(XmlNodeList? nodeList) { }

    /// <summary>
    /// No additional inner XML is required for this transform.
    /// </summary>
    protected override XmlNodeList? GetInnerXml() => null;
}
