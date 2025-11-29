using System;
using System.IO;
using System.Threading.Tasks;
using KrEtaxSample;

namespace KrEtaxSample;

/// <summary>
/// Console entry point that mirrors the Java sample mains.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            var interactiveArgs = PromptInteractiveArgs();
            if (interactiveArgs is null)
            {
                return 1;
            }

            args = interactiveArgs;
        }

        var command = args[0].ToLowerInvariant();

        try
        {
            switch (command)
            {
                case "load-pkcs12":
                    // Mirrors the LoadPKCS12.main entry point.
                    RequireArgs(args, 3, "load-pkcs12 <p12Path> <password>");
                    var (certificate, subject) = LoadPkcs12.Load(args[1], args[2]);
                    Console.WriteLine(subject);
                    Console.WriteLine(certificate);
                    break;

                case "sign-xml":
                    // Mirrors the SignXML.main entry point.
                    RequireArgs(args, 5, "sign-xml <p12Path> <password> <unsignedXml> <signedXml>");
                    var cert = SignXml.LoadPrivateKeyAndCertificate(args[1], args[2]);
                    using (var input = File.OpenRead(args[3]))
                    using (var output = File.Open(args[4], FileMode.Create, FileAccess.Write))
                    {
                        SignXml.Sign(cert, input, output);
                    }
                    Console.WriteLine($"Signed XML written to {args[4]}");
                    break;

                case "save-rvalue":
                    // Mirrors the SaveRvalue.main entry point.
                    RequireArgs(args, 4, "save-rvalue <p12Path> <password> <outputRvalue>");
                    var rvalue = SaveRvalue.ExtractRvalue(args[1], args[2]);
                    File.WriteAllBytes(args[3], rvalue);
                    Console.WriteLine($"R-value extracted to {args[3]} ({rvalue.Length} bytes)");
                    break;

                case "package-tax-invoice":
                    // Mirrors the PackageTaxInvoice.main entry point.
                    RequireArgs(args, 4, "package-tax-invoice <rvaluePath> <signedXmlPath> <derOutput>");
                    PackageTaxInvoice.WritePackage(args[1], args[2], args[3]);
                    Console.WriteLine($"TaxInvoicePackage written to {args[3]}");
                    break;

                case "encrypt-cms":
                    // Mirrors the EncryptWithCMS.main entry point.
                    RequireArgs(args, 5, "encrypt-cms <rvaluePath> <xmlPath> <encryptedOutput> <recipientCert>");
                    EncryptWithCms.Encrypt(args[1], args[2], args[3], args[4]);
                    Console.WriteLine($"CMS envelope written to {args[3]}");
                    break;

                case "submit-with-soap":
                    // Mirrors the SubmitWithSOAP.main entry point.
                    RequireArgs(args, 5, "submit-with-soap <p12Path> <password> <cmsEncryptedFile> <endpoint>");
                    var response = await SubmitWithSoap.SubmitAsync(args[1], args[2], args[3], args[4]);
                    Console.WriteLine($"HTTP {(int)response.StatusCode} {response.StatusCode}");
                    Console.WriteLine(await response.Content.ReadAsStringAsync());
                    break;

                default:
                    PrintUsage();
                    return 1;
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static string[]? PromptInteractiveArgs()
    {
        Console.WriteLine("Interactive mode: choose a command to run.");
        PrintUsage();

        Console.Write("Command: ");
        var command = ReadRequired();
        if (command is null)
        {
            return null;
        }

        switch (command.ToLowerInvariant())
        {
            case "load-pkcs12":
                var p12Path = ReadRequired("Path to PKCS#12 file: ");
                var p12Password = ReadRequired("Password: ");
                if (p12Path is null || p12Password is null)
                {
                    return null;
                }

                return new[]
                {
                    command,
                    p12Path,
                    p12Password,
                };

            case "sign-xml":
                var signXmlP12Path = ReadRequired("Path to PKCS#12 file: ");
                var signXmlPassword = ReadRequired("Password: ");
                var unsignedXml = ReadRequired("Unsigned XML path: ");
                var signedXmlOutput = ReadRequired("Signed XML output path: ");
                if (signXmlP12Path is null || signXmlPassword is null || unsignedXml is null || signedXmlOutput is null)
                {
                    return null;
                }

                return new[]
                {
                    command,
                    signXmlP12Path,
                    signXmlPassword,
                    unsignedXml,
                    signedXmlOutput,
                };

            case "save-rvalue":
                var saveRvalueP12Path = ReadRequired("Path to PKCS#12 file: ");
                var saveRvaluePassword = ReadRequired("Password: ");
                var rvalueOutput = ReadRequired("Output R-value path: ");
                if (saveRvalueP12Path is null || saveRvaluePassword is null || rvalueOutput is null)
                {
                    return null;
                }

                return new[]
                {
                    command,
                    saveRvalueP12Path,
                    saveRvaluePassword,
                    rvalueOutput,
                };

            case "package-tax-invoice":
                var rvaluePath = ReadRequired("R-value path: ");
                var signedXmlPath = ReadRequired("Signed XML path: ");
                var derOutput = ReadRequired("DER output path: ");
                if (rvaluePath is null || signedXmlPath is null || derOutput is null)
                {
                    return null;
                }

                return new[]
                {
                    command,
                    rvaluePath,
                    signedXmlPath,
                    derOutput,
                };

            case "encrypt-cms":
                var encryptRvalue = ReadRequired("R-value path: ");
                var encryptXml = ReadRequired("XML path: ");
                var encryptOutput = ReadRequired("Encrypted output path: ");
                var recipientCert = ReadRequired("Recipient certificate path: ");
                if (encryptRvalue is null || encryptXml is null || encryptOutput is null || recipientCert is null)
                {
                    return null;
                }

                return new[]
                {
                    command,
                    encryptRvalue,
                    encryptXml,
                    encryptOutput,
                    recipientCert,
                };

            case "submit-with-soap":
                var submitP12 = ReadRequired("Path to PKCS#12 file: ");
                var submitPassword = ReadRequired("Password: ");
                var cmsEncryptedFile = ReadRequired("CMS encrypted file path: ");
                var endpoint = ReadRequired("Endpoint URL: ");
                if (submitP12 is null || submitPassword is null || cmsEncryptedFile is null || endpoint is null)
                {
                    return null;
                }

                return new[]
                {
                    command,
                    submitP12,
                    submitPassword,
                    cmsEncryptedFile,
                    endpoint,
                };

            default:
                Console.Error.WriteLine("Unknown command.");
                return null;
        }
    }

    private static string? ReadRequired(string prompt = "")
    {
        if (!string.IsNullOrEmpty(prompt))
        {
            Console.Write(prompt);
        }

        var value = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(value))
        {
            Console.Error.WriteLine("A value is required.");
            return null;
        }

        return value;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: dotnet run --project src/KrEtaxSample -- <command> [args...]");
        Console.WriteLine();
        Console.WriteLine("Commands (mirroring Java mains):");
        Console.WriteLine("  load-pkcs12 <p12Path> <password>");
        Console.WriteLine("  sign-xml <p12Path> <password> <unsignedXml> <signedXml>");
        Console.WriteLine("  save-rvalue <p12Path> <password> <outputRvalue>");
        Console.WriteLine("  package-tax-invoice <rvaluePath> <signedXmlPath> <derOutput>");
        Console.WriteLine("  encrypt-cms <rvaluePath> <xmlPath> <encryptedOutput> <recipientCert>");
        Console.WriteLine("  submit-with-soap <p12Path> <password> <cmsEncryptedFile> <endpoint>");
    }

    private static void RequireArgs(string[] args, int count, string usage)
    {
        if (args.Length < count)
        {
            throw new ArgumentException($"Insufficient arguments. Usage: {usage}");
        }
    }
}
