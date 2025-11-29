using System.IO;
using KrEtaxSample.Nts.Asn1;
using Org.BouncyCastle.Asn1;

namespace KrEtaxSample;

/// <summary>
/// C# port of com.barostudio.PackageTaxInvoice.
/// </summary>
public static class PackageTaxInvoice
{
    /// <summary>
    /// Mirrors PackageTaxInvoice.main in PackageTaxInvoice.java.
    /// </summary>
    public static void WritePackage(string rvaluePath, string signedXmlPath, string derOutputPath)
    {
        var pkg = new TaxInvoicePackage(new TaxInvoiceData(ReadAll(rvaluePath), ReadAll(signedXmlPath)));

        using var output = File.Open(derOutputPath, FileMode.Create, FileAccess.Write);
        using var derStream = Asn1OutputStream.Create(output);
        derStream.WriteObject(pkg);
    }

    /// <summary>
    /// Mirrors PackageTaxInvoice.readAll in PackageTaxInvoice.java.
    /// </summary>
    public static byte[] ReadAll(string file) => File.ReadAllBytes(file);
}
