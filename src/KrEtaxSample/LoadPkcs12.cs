using System.Security.Cryptography.X509Certificates;

namespace KrEtaxSample;

/// <summary>
/// C# port of com.barostudio.LoadPKCS12.
/// </summary>
public static class LoadPkcs12
{
    /// <summary>
    /// Mirrors LoadPKCS12.main in LoadPKCS12.java.
    /// </summary>
    public static (X509Certificate2 Certificate, string Subject) Load(string p12Path, string password)
    {
        var certificate = new X509Certificate2(p12Path, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        return (certificate, certificate.Subject);
    }
}
