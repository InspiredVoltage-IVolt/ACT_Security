using ACT.Core.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ACT.Core.Security
{


    /// <summary>
    /// Default Encryption Plugin - Used in Non Absolut Secure Places
    /// </summary>
    internal class ACT_Core_Security
    {
        internal string _EncryptionKey = "DIPIsCool1234som4eTi4m4esYo4uJu4s24tH4a4ve23T4od4oIt2D44I4PCool4Ness";

        internal bool HealthCheck()
        {
            return true;
        }

        /// <summary>
        /// Internal Encryption Routine
        /// </summary>
        /// <param name="ClearText">Text To Be Encrypted</param>
        /// <returns>Encrypted String Duh..</returns>
        internal string Encrypt(string ClearText)
        {
            return Encrypt(ClearText, _EncryptionKey);
        }

        internal byte[] Encrypt(byte[] clearData, byte[] Key, byte[] IV)
        {

            // Create a MemoryStream that is going to accept the encrypted bytes

            using (MemoryStream ms = new MemoryStream())
            {
                var alg = Aes.Create();
                alg.Key = Key;
                alg.IV = IV;

                using (CryptoStream cs = new CryptoStream(ms, alg.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(clearData, 0, clearData.Length);
                    cs.Close();
                    byte[] encryptedData = ms.ToArray();
                    return encryptedData;
                }
            }

        }

        internal void CheckPasswordLength(string Password)
        {
            if (Password.NullOrEmpty() || Password.Length < 3)
            {
                throw new System.InvalidOperationException("Password is invalid.  Must be at least 3 characters long");
            }
        }

        /// <summary>
        /// <para>Encrypt</para> a string into a string using a password
        /// </summary>
        /// <param name="clearText">Text to be Encrypted</param>
        /// <param name="Password">Password to use</param>
        /// <returns>Encrypted Base 64 String</returns>
        /// <exception cref="System.InvalidOperationException">Throw if Password is Empty or clearText is Empty</exception>     
        internal string Encrypt(string clearText, string Password)
        {

            CheckPasswordLength(Password);

            // First we need to turn the input string into a byte array.

            byte[] clearBytes = System.Text.Encoding.UTF8.GetBytes(clearText);

            // Then, we need to turn the password into Key and IV
            // We are using salt to make it harder to guess our key using a dictionary attack -
            // trying to guess a password by enumerating all possible words.

            return Convert.ToBase64String(Encrypt(clearBytes, Password));
        }

        /// <summary>
        /// Encrypt a byte array into a encrypted byte array using a password <paramref name="clearData"/>
        /// </summary>
        /// <seealso cref="Encrypt(byte[],string)"/>
        /// <param name="clearData">Byte Array to be Encrypted</param>
        /// <param name="Password">Password to use</param>
        /// <returns>Encrypted Byte Array</returns>
        /// <exception cref="System.InvalidOperationException">Throw if Password is Empty or clearText is Empty</exception>
        internal byte[] Encrypt(byte[] clearData, string Password)
        {

            CheckPasswordLength(Password);
            // We need to turn the password into Key and IV.
            // We are using salt to make it harder to guess our key using a dictionary attack -
            // trying to guess a password by enumerating all possible words.

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

            // Now get the key/IV and do the encryption using the function that accepts byte arrays.
            // Using PasswordDeriveBytes object we are first getting 32 bytes for the Key
            // (the default Rijndael key length is 256bit = 32bytes) and then 16 bytes for the IV.
            // IV should always be the block size, which is by default 16 bytes (128 bit) for Rijndael.
            // If you are using DES/TripleDES/RC2 the block size is 8 bytes and so should be the IV size.
            // You can also read KeySize/BlockSize properties off the algorithm to find out the sizes.

            return Encrypt(clearData, pdb.GetBytes(32), pdb.GetBytes(16));
        }

        /// <summary>
        /// Encrypt a file into another file using a password
        /// </summary>
        /// <param name="fileIn">File To Encrypt</param>
        /// <param name="fileOut">Output File To Encrpy to</param>
        /// <param name="Password">Password to encrypt the file with</param>
        /// <exception cref="System.IO.FileNotFoundException">Source File Not Found Or Output file can't be Created</exception>
        /// <exception cref="System.InvalidOperationException">Throw if Password is Empty or clearText is Empty</exception>        
        internal void Encrypt(string fileIn, string fileOut, string Password)
        {
            CheckPasswordLength(Password);
            // First we are going to open the file streams
            if (!File.Exists(fileIn)) { throw new System.IO.FileNotFoundException("Input file not found"); }

            FileStream fsIn = new FileStream(fileIn, FileMode.Open, FileAccess.Read);
            FileStream fsOut;
            try
            {
                fsOut = new FileStream(fileOut, FileMode.OpenOrCreate, FileAccess.Write);
            }
            catch (Exception ex)
            {
                throw new System.IO.FileNotFoundException("Output file can not be created/opened", ex);
            }

            // Then we are going to derive a Key and an IV from the Password and create an algorithm
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

            Aes alg = Aes.Create();
            alg.Key = pdb.GetBytes(32);
            alg.IV = pdb.GetBytes(16);

            // Now create a crypto stream through which we are going to be pumping data.
            // Our fileOut is going to be receiving the encrypted bytes.

            CryptoStream cs = new CryptoStream(fsOut, alg.CreateEncryptor(), CryptoStreamMode.Write);

            // Now will will initialize a buffer and will be processing the input file in chunks.
            // This is done to avoid reading the whole file (which can be huge) into memory.

            int bufferLen = 4096;
            byte[] buffer = new byte[bufferLen];
            int bytesRead;

            do
            {
                // read a chunk of data from the input file
                bytesRead = fsIn.Read(buffer, 0, bufferLen);

                // encrypt it
                cs.Write(buffer, 0, bytesRead);
            } while (bytesRead != 0);

            // close everything
            cs.Close(); // this will also close the unrelying fsOut stream
            fsIn.Close();
        }

        /// <summary>
        /// Decrypt using Internal Encryption
        /// </summary>
        /// <param name="ClearText">String to Unencrypt</param>
        /// <returns>Clear Text.  Suprise!!!</returns>
        internal string Decrypt(string ClearText)
        {
            return Decrypt(ClearText, _EncryptionKey);
        }

        /// <summary>
        /// Decrypt a byte array into a byte array using a key and an IV
        /// </summary>
        /// <param name="cipherData"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns>byte Array</returns> 
        internal byte[] Decrypt(byte[] cipherData, byte[] Key, byte[] IV)
        {

            // Create a MemoryStream that is going to accept the decrypted bytes
            using (MemoryStream ms = new MemoryStream())
            {

                // Create a symmetric algorithm.
                // We are going to use Rijndael because it is strong and available on all platforms.
                // You can use other algorithms, to do so substitute the next line with something like
                //                      TripleDES alg = TripleDES.Create();
                Aes alg = Aes.Create();

                // Now set the key and the IV.
                // We need the IV (Initialization Vector) because the algorithm is operating in its default
                // mode called CBC (Cipher Block Chaining). The IV is XORed with the first block (8 byte)
                // of the data after it is decrypted, and then each decrypted block is XORed with the previous
                // cipher block. This is done to make encryption more secure.
                // There is also a mode called ECB which does not need an IV, but it is much less secure.

                alg.Key = Key;
                alg.IV = IV;

                // Create a CryptoStream through which we are going to be pumping our data.
                // CryptoStreamMode.Write means that we are going to be writing data to the stream
                // and the output will be written in the MemoryStream we have provided.

                CryptoStream cs = new CryptoStream(ms, alg.CreateDecryptor(), CryptoStreamMode.Write);

                // Write the data and make it do the decryption

                cs.Write(cipherData, 0, cipherData.Length);

                // Close the crypto stream (or do FlushFinalBlock).
                // This will tell it that we have done our decryption and there is no more data coming in,
                // and it is now a good time to remove the padding and finalize the decryption process.

                cs.Close();

                // Now get the decrypted data from the MemoryStream.
                // Some people make a mistake of using GetBuffer() here, which is not the right way.

                byte[] decryptedData = ms.ToArray();

                return decryptedData;
            }
        }


        /// <summary>
        /// Decrypt a string into a string using a password
        /// </summary>
        /// <param name="cipherText">Encrypted Text (Base64)</param>
        /// <param name="Password">PAssword to use (Must be 3 Characters)</param>
        /// <returns>Unencrypted String</returns>
        /// <exception cref="System.InvalidOperationException">Throw if Password is Empty or cipherText is Empty</exception>
        internal string Decrypt(string cipherText, string Password)
        {
            CheckPasswordLength(Password);
            // First we need to turn the input string into a byte array.
            // We presume that Base64 encoding was used
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            // Then, we need to turn the password into Key and IV
            // We are using salt to make it harder to guess our key using a dictionary attack -
            // trying to guess a password by enumerating all possible words.

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

            byte[] decryptedData = Decrypt(cipherBytes, pdb.GetBytes(32), pdb.GetBytes(16));

            // Now we need to turn the resulting byte array into a string.
            // A common mistake would be to use an Encoding class for that. It does not work
            // because not all byte values can be represented by characters.
            // We are going to be using Base64 encoding that is designed exactly for what we are
            // trying to do.

            return System.Text.Encoding.Unicode.GetString(decryptedData);
        }

        /// <summary>
        /// Decrypt byte array into a byte array using a password
        /// </summary>
        /// <param name="cipherData">Encrypted Text (Base64)</param>
        /// <param name="Password">PAssword to use (Must be 3 Characters)</param>
        /// <returns>Unencrypted Byte Array</returns>
        /// <exception cref="System.InvalidOperationException">Throw if Password is Empty or cipherText is Empty</exception>
        internal byte[] Decrypt(byte[] cipherData, string Password)
        {
            CheckPasswordLength(Password);
            // We need to turn the password into Key and IV.
            // We are using salt to make it harder to guess our key using a dictionary attack -
            // trying to guess a password by enumerating all possible words.
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

            return Decrypt(cipherData, pdb.GetBytes(32), pdb.GetBytes(16));
        }

        /// <summary>
        /// Decrypt a file into another file using a password
        /// </summary>
        /// <param name="fileIn">File to Decrypt</param>
        /// <param name="fileOut">Output File</param>
        /// <param name="Password">Password (3 Character Minimum)</param>
        /// <exception cref="System.IO.FileNotFoundException">Source File Not Found Or Output file can't be Created</exception>
        /// <exception cref="System.InvalidOperationException">Throw if Password is Empty or clearText is Empty</exception>
        internal void Decrypt(string fileIn, string fileOut, string Password)
        {

            CheckPasswordLength(Password);
            // First we are going to open the file streams
            if (!File.Exists(fileIn)) { throw new System.IO.FileNotFoundException("Input file not found"); }

            FileStream fsIn = new FileStream(fileIn, FileMode.Open, FileAccess.Read);
            FileStream fsOut;
            try
            {
                fsOut = new FileStream(fileOut, FileMode.OpenOrCreate, FileAccess.Write);
            }
            catch (Exception ex)
            {
                throw new System.IO.FileNotFoundException("Output file can not be created/opened", ex);
            }
            // Then we are going to derive a Key and an IV from the Password and create an algorithm

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

            Aes alg = Aes.Create();

            alg.Key = pdb.GetBytes(32);
            alg.IV = pdb.GetBytes(16);

            // Now create a crypto stream through which we are going to be pumping data.
            // Our fileOut is going to be receiving the Decrypted bytes.

            CryptoStream cs = new CryptoStream(fsOut, alg.CreateDecryptor(), CryptoStreamMode.Write);

            // Now will will initialize a buffer and will be processing the input file in chunks.
            // This is done to avoid reading the whole file (which can be huge) into memory.

            int bufferLen = 4096;
            byte[] buffer = new byte[bufferLen];
            int bytesRead;
            do
            {
                // read a chunk of data from the input file
                bytesRead = fsIn.Read(buffer, 0, bufferLen);

                // Decrypt it
                cs.Write(buffer, 0, bytesRead);

            } while (bytesRead != 0);

            // close everything

            cs.Close(); // this will also close the unrelying fsOut stream

            fsIn.Close();
        }

        /// <summary>
        /// Creates A MD5 Hash from a String
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal string StringToMD5(string value)
        {
	        using (var _MD5 = MD5.Create())
            {
                byte[] bs = Encoding.UTF8.GetBytes(value);
                bs = _MD5.ComputeHash(bs);
                return Convert.ToBase64String(bs);
            }
        }

        /// <summary>
        /// Creates A MD5 Hash from a String
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal string StringToMD5_ACT(string value, bool removeDash = true)
        {
            using (var _MD5 = MD5.Create())
            {
                byte[] bs = Encoding.UTF8.GetBytes(value.Reverse().ToString());
                bs = _MD5.ComputeHash(bs);
                return GetBase64StringFromByteArray(bs, removeDash);
            }
        }

        /// <summary>byte[] to String</summary>
        /// <param name="hash">byte array to</param>
        /// <returns>Base64 String</returns>
        internal static string GetBase64StringFromByteArray(byte[] hash, bool removeDash = true)
        {
            if (removeDash) { return Convert.ToBase64String(hash).Replace("-", ""); }
            else { return Convert.ToBase64String(hash); }
        }

        /// <summary>SHA 256</summary>
        /// <param name="value"></param>
        /// <returns>Base64 String</returns>
        internal string StringToSHA256Hash(string value, bool removeDash = true)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(value);
                byte[] hash = sha256.ComputeHash(bytes);
                return GetBase64StringFromByteArray(hash);
            }
        }

        /// <summary>SHA 512</summary>
        /// <param name="value">String To ComputeHash</param>
        /// <returns>Base64 String</returns>
        internal string StringToSHA512Hash(string value, bool removeDash = true)
        {
            using (var sha512 = SHA512.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(value);
                byte[] hash = sha512.ComputeHash(bytes);
                return GetBase64StringFromByteArray(hash);
            }
        }


        internal byte[] Encrypt(byte[] clearData, string Salt, byte[] IV, string Password)
        {
            return this.Encrypt(clearData, Password.ToBytes(), IV);
        }

        internal byte[] Decrypt(byte[] cipherData, string Salt, byte[] IV, string Password)
        {
            return this.Decrypt(cipherData, Password.ToBytes(), IV);
        }

        internal string NarrowEncrypt(string ClearText, bool UseUser = true, bool UseMachine = false)
        {
            if (UseUser) { return ProtectedData.Protect(ClearText.ToBytes(), _EncryptionKey.ToBytes(), DataProtectionScope.CurrentUser).ToBase64String(); }
            else { return ProtectedData.Protect(ClearText.ToBytes(), _EncryptionKey.ToBytes(), DataProtectionScope.LocalMachine).ToBase64String(); }
        }

        internal string NarrowDecrypt(string ClearText, bool UseUser = true, bool UseMachine = false)
        {
            if (UseUser) { return System.Text.Encoding.UTF8.GetString(ProtectedData.Unprotect(ClearText.FromBase64String(), _EncryptionKey.ToBytes(), DataProtectionScope.CurrentUser)); }
            else { return System.Text.Encoding.UTF8.GetString(ProtectedData.Unprotect(ClearText.FromBase64String(), _EncryptionKey.ToBytes(), DataProtectionScope.LocalMachine)); }
        }
    }

}
