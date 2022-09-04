using System.Text;
using ACT.Core.Extensions;
using ACT.Core.Security.BouncyCastleEncryption;
using ACT.Core.Security.Hashing;
using ACT_Security_Test_Console;
using NLog.Targets;

/// <summary>
/// ACTLicFileEncryp = Encryption Key For Lic File.
/// </summary>
namespace ACT.SecurityTestConsole // Note: actual namespace depends on the project name.
{
    public static class Program
    {
        public static void Main(string[] args)
        {
        startArea:
            Console.WriteLine("       HASHING      ");
            Console.WriteLine("----------------------------------");
            Console.WriteLine("A - SHA512");
            Console.WriteLine("B - SHA256");
            Console.WriteLine("----------------------------------");
            Console.WriteLine("       ENCODING     ");
            Console.WriteLine("----------------------------------");
            Console.WriteLine("S - String To Base64 Encoding");
            Console.WriteLine("U - String To URL Encoding");
            Console.WriteLine("O - Protect File");
            Console.WriteLine("N - Un-Protect File");
            Console.WriteLine("----------------------------------");
            Console.WriteLine("E - EXIT");
            Console.WriteLine("----------------------------------");
            Console.Write("Your Choice> ");
            var C = Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine();
            var kc = C.KeyChar.ToString().ToLower();

            if (kc == "a" || kc == "b" || kc == "e")
            {
                Console.Write("String To Hash> ");
                var keyToHash = Console.ReadLine();

                Console.WriteLine("--------------------");
                Console.WriteLine();
                if (kc == "a")
                {
                    Console.WriteLine("<BEGIN>");
                    Console.WriteLine(SHAHashing.ToSHA512Hash(keyToHash, false));
                    Console.WriteLine("<END>");
                }
                else if (kc == "b")
                {
                    Console.WriteLine("<BEGIN>");
                    Console.WriteLine(SHAHashing.StringToSHA256Hash(keyToHash, false));
                    Console.WriteLine("<END>");
                }
                else if (kc == "e")
                {
                    Console.Write("Press Any Key To Exit: ");
                    Console.ReadKey();

                    return;
                }

                Console.Write("Completed... Press Any Key To Continue");
                Console.ReadKey();
            }
            if (kc == "s" || kc == "u")
            {
                if (kc == "s")
                {
                b64label:
                    Console.Write("Press E to Encode and D to Decode> ");
                    var _ED = Console.ReadKey().ToString();

                    // Detect Invalid Menu Selections
                    if (_ED == null || (!string.Equals(_ED, "e", StringComparison.CurrentCultureIgnoreCase) &&
                                        !string.Equals(_ED, "d", StringComparison.CurrentCultureIgnoreCase)))
                    {
                        Console.Write("Invalid Selection. Press Any Key To Continue");
                        Console.ReadKey();

                        goto b64label;
                    }

                    Console.Write("String To Encode/Decode> ");
                    var StringToEncodeDecode = Console.ReadLine();

                    if (StringToEncodeDecode == null)
                    {
                        Console.Write("String Cannot be null");
                        Console.ReadKey();

                        goto b64label;
                    }

                    Console.WriteLine("--------------------");
                    Console.WriteLine();
                    if (string.Equals(_ED, "e", StringComparison.CurrentCultureIgnoreCase))
                    {
                        Console.WriteLine("<ENCODED-START>");
                        var ddd = StringToEncodeDecode.ToBase64();
                        Console.WriteLine(ddd);
                        Console.WriteLine("<END>");
                        Console.Write("Completed... Press Any Key To Continue");
                        Console.ReadKey();
                    }
                    else
                    {
                        Console.WriteLine("<DECODED-START>");
                        var ddd = StringToEncodeDecode.FromBase64();
                        Console.WriteLine(ddd);
                        Console.WriteLine("<END>");
                        Console.Write("Completed... Press Any Key To Continue");
                        Console.ReadKey();
                    }
                }
                else if (kc == "u")
                {

                urllabel:
                    Console.Write("Press E to Encode and D to Decode> ");
                    var _ED = Console.ReadLine();

                    // Detect Invalid Menu Selections
                    if (_ED == null || (!string.Equals(_ED, "e", StringComparison.CurrentCultureIgnoreCase) &&
                                        !string.Equals(_ED, "d", StringComparison.CurrentCultureIgnoreCase)))
                    {
                        Console.Write("Invalid Selection. Press Any Key To Continue");
                        Console.ReadKey();

                        goto urllabel;
                    }

                    Console.Write("String To Encode/Decode> ");
                    var StringToEncodeDecode = Console.ReadLine();

                    if (StringToEncodeDecode == null)
                    {
                        Console.Write("String Cannot be null");
                        Console.ReadKey();

                        goto urllabel;
                    }

                    Console.WriteLine("--------------------");
                    Console.WriteLine();
                    if (string.Equals(_ED, "e", StringComparison.CurrentCultureIgnoreCase))
                    {
                        Console.WriteLine("<ENCODED-START>");
                        var ddd = StringToEncodeDecode.URLEncode(true);
                        Console.WriteLine(ddd);
                        Console.WriteLine("<END>");
                    }
                    else
                    {
                        Console.WriteLine("<DECODED-START>");
                        var ddd = StringToEncodeDecode.URLDecode();
                        Console.WriteLine(ddd);
                        Console.WriteLine("<END>");
                    }

                    Console.Write("Press Any Key To Exit: ");
                    Console.ReadKey();
                }
            }
            if (kc == "o" || kc == "n")
            {
            startprotect:
                if (kc == "o")
                {
                    Console.Write("File To Protect: ");
                    var FileToProtect = Console.ReadLine();
                    if (FileToProtect == null) { goto startArea; }

                    if (FileToProtect.FileExists())
                    {
                        var _Data = System.IO.File.ReadAllBytes(FileToProtect);
                        if (_Data == null) { throw new Exception("Error Protecting Data  - Data is Blank and Null"); }

                        var _DataBytes = ACT.Core.Security.ProtectData.Protect(_Data, true);

                        string _ProtectedFileName = Path.ChangeExtension(FileToProtect, Path.GetExtension(FileToProtect) + "ACTP");

                        System.IO.File.WriteAllBytes(_ProtectedFileName, _DataBytes);

                        Console.WriteLine("Done Protecting File: " + FileToProtect + ", Press Any Key To Continue.");
                        Console.ReadKey();
                        goto startArea;
                    }
                }
                else if (kc == "n")
                {
                    Console.Write("File To UnProtect: ");
                    var FileToUnProtect = Console.ReadLine();

                    if (FileToUnProtect.FileExists())
                    {
                        var _Data = System.IO.File.ReadAllBytes(FileToUnProtect);
                        if (_Data == null) { throw new Exception("Error Protecting Data  - Data is Blank and Null"); }

                        var _DataBytes = ACT.Core.Security.ProtectData.UnProtect(_Data, true);
                        System.IO.File.WriteAllBytes(FileToUnProtect.Replace("ACTP", ""), _DataBytes);

                        Console.WriteLine("Done UnProtecting File: " + FileToUnProtect.Replace("ACTP", "") + ", Press Any Key To Continue.");
                        Console.ReadKey();
                        goto startArea;
                    }
                }
            }
            goto startArea;
        }
    }
}