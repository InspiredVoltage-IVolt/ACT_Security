using ACT.Core.Extensions;
using System.Security.Cryptography;
using System.Text;
using ACT.Core.Security.BouncyCastleEncryption;

namespace ACT.Core.Security.Encryption
{
    public class ACTEncryption : Interfaces.Security.I_Encryption, IDisposable
    {
        private string _EncryptionKey = "DIPIsCool1234som4eTi4m4esYo4uJu4s24tH4a4ve23T4od4oIt2D44I4PCool4Ness";

        private ACT_Core_Security _E = null;

        public ACTEncryption() 
        {         
            _E = new ACT_Core_Security();
        }

        public ACTEncryption(string SaltnPepper)
        {
            _EncryptionKey = SaltnPepper;       
            _E = new ACT_Core_Security();
        }

        public string EncryptString(string key, string plainText)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public  string DecryptString(string key, string cipherText)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        public string NarrowEncrypt(string ClearText, bool UseUser = true, bool UseMachine = false)
        {
            if (UseUser) { return ProtectedData.Protect(ClearText.ToBytes(), _EncryptionKey.ToBytes(), DataProtectionScope.CurrentUser).ToBase64String(); }
            else { return ProtectedData.Protect(ClearText.ToBytes(), _EncryptionKey.ToBytes(), DataProtectionScope.LocalMachine).ToBase64String(); }
        }

        public string NarrowDecrypt(string ClearText, bool UseUser = true, bool UseMachine = false)
        {
	        try
	        {
		        if (UseUser)
		        {
			        return System.Text.Encoding.UTF8.GetString (ProtectedData.Unprotect (
				        ClearText.FromBase64String (), _EncryptionKey.ToBytes (), DataProtectionScope.CurrentUser));
		        }
		        else
		        {
			        return System.Text.Encoding.UTF8.GetString (ProtectedData.Unprotect (
				        ClearText.FromBase64String (), _EncryptionKey.ToBytes (), DataProtectionScope.LocalMachine));
		        }
	        }
	        catch
	        {
		        return null;
	        }
        }

        public string Encrypt(string ClearText) { return BouncyCastleEncryption.BCEncryption.EncryptString(_EncryptionKey.ToBase64().ToSHA256(), ClearText); }

        public string Encrypt(string clearText, string Password) { return BouncyCastleEncryption.BCEncryption.EncryptString(Password, clearText); }

        public byte[] Encrypt(byte[] clearData, string Password) { return _E.Encrypt(clearData, Password); }

        public void Encrypt(string fileIn, string fileOut, string Password) { File.WriteAllBytes(fileOut, Encrypt(System.IO.File.ReadAllBytes(fileIn), Password)); }

        public byte[] Encrypt(byte[] clearData, string Salt, byte[] IV, string Password) { return _E.Encrypt(clearData, Salt, IV, Password); }

        public byte[] Decrypt(byte[] cipherData, string Salt, byte[] IV, string Password) { return _E.Decrypt(cipherData, Salt, IV, Password); }

        public string Decrypt(string ClearText) { return BCEncryption.DecryptString(_EncryptionKey.ToBase64().ToSHA256(), ClearText); }

        public string Decrypt(string cipherText, string Password) { return BCEncryption.EncryptString(Password, cipherText); }

        public byte[] Decrypt(byte[] cipherData, string Password) { return _E.Decrypt(cipherData, Password); }

        public void Decrypt(string fileIn, string fileOut, string Password) { File.WriteAllBytes(fileOut, Decrypt(System.IO.File.ReadAllBytes(fileIn), Password)); }

        [Obsolete]
        public string MD5(string value) { return _E.StringToMD5(value); }

        [Obsolete]
        public string MD5ALT(string value) { return _E.StringToMD5_ACT(value); }

        public string SHA256(string value) { return _E.StringToSHA256Hash(value); }

        public string SHA512(string value) { return _E.StringToSHA512Hash(value); }

        public bool HealthCheck()
        {
            string _stringToTest = "aaaaAAAAbbbbBBBB^55%234234**99((00555#$#@@#Q`~043948fwnm9823r";
            var _X = Encrypt("123456", _stringToTest);
            var _T = Decrypt("123456", _X);

            if (_X == _T) { return true; }
            else { return false; }
        }

        public void Dispose()
        {
            _E = null;
        }

        ~ACTEncryption()
        {
            _E = null;
        }
    }
}

