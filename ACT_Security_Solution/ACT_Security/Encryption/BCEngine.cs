using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace ACT.Core.Security.BouncyCastleEncryption
{
    public static class BCRSA
    {
        public static string RSA_EncryptMessage()
        {
            SHA256Managed hash = new SHA256Managed();
            SecureRandom randomNumber = new SecureRandom();
            byte[] encodingParam = hash.ComputeHash(Encoding.UTF8.GetBytes(randomNumber.ToString()));
            string inputMessage = "Test Message";
            UTF8Encoding utf8enc = new UTF8Encoding();

            // Converting the string message to byte array
            byte[] inputBytes = utf8enc.GetBytes(inputMessage);

            // RSAKeyPairGenerator generates the RSA Key pair based on the random number and strength of key required
            RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
            rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 1024));

            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();
            RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
            RsaKeyParameters privateKey = (RsaKeyParameters)keyPair.Private;
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), encodingParam);
            cipher.Init(true, publicKey);
            byte[] ciphered = cipher.ProcessBlock(inputBytes, 0, inputMessage.Length);
            string cipheredText = utf8enc.GetString(ciphered);

            return cipheredText;
        }

        public static void RSA_DecryptMessage ()
        {
	        // Decryption steps 
	     //   cipher.Init(false, privateKey);
	     //   byte[] deciphered = cipher.ProcessBlock(ciphered, 0, ciphered.Length);
	     //   string decipheredText = utf8enc.GetString(deciphered);
        }
    }

    public static class BCEncryption
    {
        public static BCEngine _engine = new BCEngine(new AesEngine(), Encoding.ASCII);
        public static Pkcs7Padding _padding = new Pkcs7Padding();
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
        public static string EncryptString(string key, string plainText)
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
        public static string DecryptString(string key, string plainText)
        {
            byte[] _finalKey = Create256BitKey(key);
            _engine.SetPadding(_padding);
            return _engine.Decrypt(plainText, Encoding.ASCII.GetString(_finalKey));
        }


    }


    public class BCEngine
    {
        private readonly Encoding _encoding;
        private readonly IBlockCipher _blockCipher;
        private PaddedBufferedBlockCipher _cipher;
        private IBlockCipherPadding _padding;

        public BCEngine(IBlockCipher blockCipher, Encoding encoding = null)
        {
            if (encoding == null) { encoding = Encoding.UTF8; }

            _blockCipher = blockCipher;
            _encoding = encoding;
        }

        public void SetPadding(IBlockCipherPadding padding)
        {
            if (padding != null)
                _padding = padding;
        }

        public string Encrypt(string plain, string key)
        {
            byte[] result = BouncyCastleCrypto(true, _encoding.GetBytes(plain), key);
            return Convert.ToBase64String(result);
        }

        public string Decrypt(string cipher, string key)
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

        public string AESEncryption(string plain, string key, bool fips)
        {
            BCEngine bcEngine = new BCEngine(new AesEngine(), _encoding);
            bcEngine.SetPadding(_padding);
            return bcEngine.Encrypt(plain, key);
        }

        public string AESDecryption(string cipher, string key, bool fips)
        {
            BCEngine bcEngine = new BCEngine(new AesEngine(), _encoding);
            bcEngine.SetPadding(_padding);
            return bcEngine.Decrypt(cipher, key);
        }
    }
}
