using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ACT_Security_Test_Console
{
    internal static class RSA_KeyManager
    {
        public class RsaKeyData
        {
            public string Modulus = "";
            public string Exponent = "";
            public string P = "";
            public string Q = "";
            public string DP = "";
            public string DQ = "";

            public string PubKeyXMLString = "";
        }
        public static RsaKeyData GeneratePublicAndPrivateKeys()
        {
	        using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider (4096))
	        {
				
		        // Read public key in a string  
		        var str = RSA.ToXmlString (true);

		        // Get key into parameters  
		        RSAParameters rsaKeyInfo = RSA.ExportParameters (true);

		        if (rsaKeyInfo.Modulus == null || rsaKeyInfo.Exponent == null || rsaKeyInfo.P == null ||
		            rsaKeyInfo.Q == null || rsaKeyInfo.DP == null || rsaKeyInfo.DQ == null)
		        {
			        return null;
		        }

		        RsaKeyData _M = new RsaKeyData
		        {
			        Modulus = System.Text.Encoding.UTF8.GetString (rsaKeyInfo.Modulus),
			        Exponent = System.Text.Encoding.UTF8.GetString (rsaKeyInfo.Exponent),
			        P = System.Text.Encoding.UTF8.GetString (rsaKeyInfo.P),
			        Q = System.Text.Encoding.UTF8.GetString (rsaKeyInfo.Q),
			        DP = System.Text.Encoding.UTF8.GetString (rsaKeyInfo.DP),
			        DQ = System.Text.Encoding.UTF8.GetString (rsaKeyInfo.DQ),
			        PubKeyXMLString = str
		        };

		        #region old code

		        /*
	
		        Console.WriteLine($ "Modulus: {System.Text.Encoding.UTF8.GetString(RSAKeyInfo.Modulus)}");
		        Console.WriteLine($ "Exponent: {System.Text.Encoding.UTF8.GetString(RSAKeyInfo.Exponent)}");
		        Console.WriteLine($ "P: {System.Text.Encoding.UTF8.GetString(RSAKeyInfo.P)}");
		        Console.WriteLine($ "Q: {System.Text.Encoding.UTF8.GetString(RSAKeyInfo.Q)}");
		        Console.WriteLine($ "DP: {System.Text.Encoding.UTF8.GetString(RSAKeyInfo.DP)}");
		        Console.WriteLine($ "DQ: {System.Text.Encoding.UTF8.GetString(RSAKeyInfo.DQ)}");
		        */

		        #endregion

		        return _M;
	        }
        }
    }
}
