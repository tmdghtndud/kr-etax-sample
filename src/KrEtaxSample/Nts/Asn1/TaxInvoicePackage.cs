using Org.BouncyCastle.Asn1;

namespace KrEtaxSample.Nts.Asn1;

/// <summary>
/// ASN.1 model that mirrors the original Java TaxInvoicePackage class.
/// This follows TaxInvoicePackage in com.barostudio.nts.asn1.TaxInvoicePackage.
/// </summary>
public class TaxInvoicePackage : Asn1Encodable
{
    public DerInteger Count { get; }
    public Asn1Set TaxInvoiceSet { get; }

    /// <summary>
    /// Corresponds to the sequence-parsing constructor in TaxInvoicePackage.java.
    /// </summary>
    public TaxInvoicePackage(Asn1Sequence seq)
    {
        var e = seq.GetEnumerator();
        if (!e.MoveNext())
        {
            throw new InvalidOperationException("Missing count element in TaxInvoicePackage");
        }

        Count = DerInteger.GetInstance(e.Current);

        if (!e.MoveNext())
        {
            throw new InvalidOperationException("Missing taxInvoiceSet element in TaxInvoicePackage");
        }

        TaxInvoiceSet = Asn1Set.GetInstance(e.Current);
    }

    /// <summary>
    /// Mirrors the array constructor in TaxInvoicePackage.java.
    /// </summary>
    public TaxInvoicePackage(params TaxInvoiceData[] taxInvoices)
    {
        Count = new DerInteger(taxInvoices.Length);

        var v = new Asn1EncodableVector();
        foreach (var invoice in taxInvoices)
        {
            v.Add(invoice);
        }

        TaxInvoiceSet = DerSet.FromVector(v);
    }

    /// <summary>
    /// Corresponds to TaxInvoicePackage.toASN1Primitive in TaxInvoicePackage.java.
    /// </summary>
    public override Asn1Object ToAsn1Object()
    {
        var v = new Asn1EncodableVector
        {
            Count,
            TaxInvoiceSet
        };

        return new DerSequence(v);
    }
}
