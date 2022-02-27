using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ACT.Core.Security.Encryption
{
    internal static class BCEncryption
    {
        internal static BCEngine _engine = new BCEngine(new AesEngine(), Encoding.ASCII);
        internal static Pkcs7Padding _padding = new Pkcs7Padding();
        private static readonly byte[] Salt = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };

        /// <summary>
        /// Create Key From Given Password - Ensure it is 256 bit in length
        /// </summary>
        /// <param name="password">Password to convert</param>
        /// <param name="keyBytes"></param>
        /// <returns></returns>
        private static byte[] Create256BitKey(string password)
        {
            int keyBytes = 32;
            const int Iterations = 300;            
            var keyGenerator = new Rfc2898DeriveBytes(password, Salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        /// <summary>
        /// Encrypt the string
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainText"></param>
        /// <returns></returns>
        internal static string EncryptString(string key, string plainText)
        {
            byte[] _finalKey = Create256BitKey(key);
            _engine.SetPadding(_padding);
            return _engine.Encrypt(plainText, Encoding.ASCII.GetString(_finalKey));
        }

        /// <summary>
        /// Decrypt the String
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainText"></param>
        /// <returns></returns>
        internal static string DecryptString(string key, string plainText)
        {
            byte[] _finalKey = Create256BitKey(key);
            _engine.SetPadding(_padding);
            return _engine.Decrypt(plainText, Encoding.ASCII.GetString(_finalKey));
        }


    }


    internal class BCEngine
    {
        private readonly Encoding _encoding;
        private readonly IBlockCipher _blockCipher;
        private PaddedBufferedBlockCipher _cipher;
        private IBlockCipherPadding _padding;

        internal BCEngine(IBlockCipher blockCipher, Encoding encoding)
        {
            _blockCipher = blockCipher;
            _encoding = encoding;
        }

        internal void SetPadding(IBlockCipherPadding padding)
        {
            if (padding != null)
                _padding = padding;
        }

        internal string Encrypt(string plain, string key)
        {
            byte[] result = BouncyCastleCrypto(true, _encoding.GetBytes(plain), key);
            return Convert.ToBase64String(result);
        }

        internal string Decrypt(string cipher, string key)
        {
            byte[] result = BouncyCastleCrypto(false, Convert.FromBase64String(cipher), key);
            return _encoding.GetString(result);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="forEncrypt"></param>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        private byte[] BouncyCastleCrypto(bool forEncrypt, byte[] input, string key)
        {
            try
            {
                _cipher = _padding == null ? new PaddedBufferedBlockCipher(_blockCipher) : new PaddedBufferedBlockCipher(_blockCipher, _padding);
                byte[] keyByte = _encoding.GetBytes(key);
                _cipher.Init(forEncrypt, new KeyParameter(keyByte));
                return _cipher.DoFinal(input);
            }
            catch (Org.BouncyCastle.Crypto.CryptoException ex)
            {
                throw new CryptoException(ex.Message);
            }
        }

        internal string AESEncryption(string plain, string key, bool fips)
        {
            BCEngine bcEngine = new BCEngine(new AesEngine(), _encoding);
            bcEngine.SetPadding(_padding);
            return bcEngine.Encrypt(plain, key);
        }

        internal string AESDecryption(string cipher, string key, bool fips)
        {
            BCEngine bcEngine = new BCEngine(new AesEngine(), _encoding);
            bcEngine.SetPadding(_padding);
            return bcEngine.Decrypt(cipher, key);
        }
    }
}
