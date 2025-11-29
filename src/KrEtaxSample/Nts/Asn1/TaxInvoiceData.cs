using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;

namespace KrEtaxSample.Nts.Asn1;

/// <summary>
/// ASN.1 model that mirrors the original Java TaxInvoiceData class.
/// This follows TaxInvoiceData in com.barostudio.nts.asn1.TaxInvoiceData.
/// </summary>
public class TaxInvoiceData : Asn1Encodable
{
    public Asn1OctetString SignerRvalue { get; }
    public Asn1OctetString TaxInvoice { get; }

    /// <summary>
    /// Corresponds to TaxInvoiceData.getInstance in TaxInvoiceData.java.
    /// </summary>
    public static TaxInvoiceData GetInstance(object obj)
    {
        if (obj is TaxInvoiceData data)
        {
            return data;
        }

        return new TaxInvoiceData(Asn1Sequence.GetInstance(obj));
    }

    /// <summary>
    /// Corresponds to the sequence-parsing constructor in TaxInvoiceData.java.
    /// </summary>
    public TaxInvoiceData(Asn1Sequence seq)
    {
        var e = seq.GetEnumerator();
        if (!e.MoveNext())
        {
            throw new InvalidOperationException("Missing signerRvalue element in TaxInvoiceData");
        }

        SignerRvalue = Asn1OctetString.GetInstance(e.Current);

        if (!e.MoveNext())
        {
            throw new InvalidOperationException("Missing taxInvoice element in TaxInvoiceData");
        }

        TaxInvoice = Asn1OctetString.GetInstance(e.Current);
    }

    /// <summary>
    /// Mirrors the byte array constructor in TaxInvoiceData.java.
    /// </summary>
    public TaxInvoiceData(byte[] signerRvalue, byte[] taxInvoice)
    {
        SignerRvalue = new DerOctetString(signerRvalue);
        TaxInvoice = new DerOctetString(taxInvoice);
    }

    /// <summary>
    /// Corresponds to TaxInvoiceData.toASN1Primitive in TaxInvoiceData.java.
    /// </summary>
    public override Asn1Object ToAsn1Object()
    {
        var seq = new Asn1EncodableVector
        {
            SignerRvalue,
            TaxInvoice
        };

        return new DerSequence(seq);
    }
}
