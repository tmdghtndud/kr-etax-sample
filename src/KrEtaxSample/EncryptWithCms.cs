using System;
using System.IO;
using KrEtaxSample.Nts.Asn1;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace KrEtaxSample;

/// <summary>
/// C# port of com.barostudio.EncryptWithCMS.
/// </summary>
public static class EncryptWithCms
{
    /// <summary>
    /// Mirrors EncryptWithCMS.main in EncryptWithCMS.java.
    /// </summary>
    public static void Encrypt(string rvaluePath, string xmlPath, string encryptedFilePath, string recipientCertPath)
    {
        var packageBytes = GetTaxInvoicePackageAsBytes(rvaluePath, xmlPath);

        var certificate = LoadRecipientCertificate(recipientCertPath);
        var generator = new CmsEnvelopedDataGenerator();
        generator.AddKeyTransRecipient(certificate);

        var cmsData = generator.Generate(new CmsProcessableByteArray(packageBytes), CmsEnvelopedGenerator.DesEde3Cbc);
        File.WriteAllBytes(encryptedFilePath, cmsData.GetEncoded());
    }

    /// <summary>
    /// Mirrors EncryptWithCMS.getTaxInvoicePackageAsBytes in EncryptWithCMS.java.
    /// </summary>
    public static byte[] GetTaxInvoicePackageAsBytes(string rvalueFile, string xmlFile)
    {
        var signerRvalue = ReadAll(rvalueFile);
        var taxInvoice = ReadAll(xmlFile);

        var data = new TaxInvoiceData(signerRvalue, taxInvoice);
        var pkg = new TaxInvoicePackage(data);

        using var baos = new MemoryStream();
        using var asn1Stream = Asn1OutputStream.Create(baos);
        asn1Stream.WriteObject(pkg);
        asn1Stream.Flush();
        return baos.ToArray();
    }

    /// <summary>
    /// Mirrors EncryptWithCMS.readAll in EncryptWithCMS.java.
    /// </summary>
    public static byte[] ReadAll(string file)
    {
        return File.ReadAllBytes(file);
    }

    /// <summary>
    /// Mirrors EncryptWithCMS.kmCert in EncryptWithCMS.java.
    /// </summary>
    public static X509Certificate LoadRecipientCertificate(string certificatePath)
    {
        using var fs = File.OpenRead(certificatePath);
        var parser = new X509CertificateParser();
        return parser.ReadCertificate(fs);
    }
}
