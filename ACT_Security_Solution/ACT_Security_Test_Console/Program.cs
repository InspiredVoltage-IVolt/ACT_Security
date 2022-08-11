using ACT.Core.Extensions;
using ACT.Core.Security.BouncyCastleEncryption;
using ACT.Core.Security.Hashing;
using ACT_Security_Test_Console;
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
                    if (_ED == null || (!string.Equals(_ED, "e", StringComparison.CurrentCultureIgnoreCase) && !string.Equals(_ED, "d", StringComparison.CurrentCultureIgnoreCase)))
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
	                if (_ED == null || (!string.Equals(_ED, "e", StringComparison.CurrentCultureIgnoreCase) && !string.Equals(_ED, "d", StringComparison.CurrentCultureIgnoreCase)))
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

            goto startArea;

            /*
            //ByAmx"nMfBi~k}JR

            var _PPK = RSA_KeyManager.GeneratePublicAndPrivateKeys();
    Console.WriteLine(_PPK.PubKeyXMLString);

            var _PPK1 = RSA_KeyManager.GeneratePublicAndPrivateKeys();
    Console.WriteLine(_PPK1.PubKeyXMLString);

            Console.ReadKey();
            return;


            string _Enca = ACT.Core.Security.BouncyCastleEncryption.BCEncryption.EncryptString("MarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasd", "Fuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck youFuck you");
    Console.WriteLine(_Enca);

            string _Encb = ACT.Core.Security.BouncyCastleEncryption.BCEncryption.DecryptString("MarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasdMarkAliczasasdasdasdasd", _Enca);
    Console.WriteLine(_Encb);

            Console.ReadKey();
            */

        }
    }
}