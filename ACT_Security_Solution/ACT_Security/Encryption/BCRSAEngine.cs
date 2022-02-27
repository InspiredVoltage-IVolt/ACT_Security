using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ACT.Core.Security.Encryption.RSA
{
    internal class RsaPrivateKeyParameters
    {
        internal byte[] D { get; set; }
        internal byte[] P { get; set; }
        internal byte[] Q { get; set; }
        internal byte[] DP { get; set; }
        internal byte[] DQ { get; set; }
        internal byte[] InverseQ { get; set; }
        internal byte[] Modulus { get; set; }
        internal byte[] Exponent { get; set; }
    }

    internal class RsaPublicKeyParameters
    {
        internal byte[] Modulus { get; set; }
        internal byte[] Exponent { get; set; }
    }

    internal static class RSAParametersExtensions
    {
        internal static RsaPrivateKeyParameters ToPrivateKeyParameters(this RsaPrivateKeyParameters rsaParameters)
        {
            return new RsaPrivateKeyParameters
            {
                D = rsaParameters.D,
                P = rsaParameters.P,
                Q = rsaParameters.Q,
                DP = rsaParameters.DP,
                DQ = rsaParameters.DQ,
                InverseQ = rsaParameters.InverseQ,
                Modulus = rsaParameters.Modulus,
                Exponent = rsaParameters.Exponent,
            };
        }

        internal static RsaPublicKeyParameters ToPublicKeyParameters(this RsaPublicKeyParameters rsaParameters)
        {
            return new RsaPublicKeyParameters
            {
                Modulus = rsaParameters.Modulus,
                Exponent = rsaParameters.Exponent,
            };
        }
    }
    internal static class RsaPublicKeyParametersExtensions
    {
        internal static RSAParameters ToRSAParameters(this RsaPublicKeyParameters rsaPublicKeyParameters)
        {
            return new RSAParameters
            {
                Modulus = rsaPublicKeyParameters.Modulus,
                Exponent = rsaPublicKeyParameters.Exponent,
            };
        }

        internal static RsaKeyParameters ToRsaKeyParameters(this RsaPublicKeyParameters rsaPublicKeyParameters)
        {
            return new RsaKeyParameters(
                false,
                new BigInteger(1, rsaPublicKeyParameters.Modulus),
                new BigInteger(1, rsaPublicKeyParameters.Exponent));
        }
    }
    internal static class AsymmetricKeyParameterExtensions
    {
        internal static RsaPrivateKeyParameters ToPrivateKeyParameters(this AsymmetricKeyParameter keyParameters)
        {
            var rsaParameters = keyParameters as RsaPrivateCrtKeyParameters;
            return new RsaPrivateKeyParameters
            {
                D = rsaParameters.Exponent.ToByteArrayUnsigned(),
                P = rsaParameters.P.ToByteArrayUnsigned(),
                Q = rsaParameters.Q.ToByteArrayUnsigned(),
                DP = rsaParameters.DP.ToByteArrayUnsigned(),
                DQ = rsaParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaParameters.QInv.ToByteArrayUnsigned(),
                Modulus = rsaParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaParameters.PublicExponent.ToByteArrayUnsigned(),
            };
        }

        internal static RsaPublicKeyParameters ToPublicKeyParameters(this AsymmetricKeyParameter keyParameters)
        {
            var rsaParameters = keyParameters as RsaKeyParameters;
            return new RsaPublicKeyParameters
            {
                Modulus = rsaParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaParameters.Exponent.ToByteArrayUnsigned(),
            };
        }
    }
    internal static class RsaPrivateKeyParametersExtensions
    {
        internal static RSAParameters ToRSAParameters(this RsaPrivateKeyParameters rsaPrivateKeyParameters)
        {
            return new RSAParameters
            {
                D = rsaPrivateKeyParameters.D,
                P = rsaPrivateKeyParameters.P,
                Q = rsaPrivateKeyParameters.Q,
                DP = rsaPrivateKeyParameters.DP,
                DQ = rsaPrivateKeyParameters.DQ,
                InverseQ = rsaPrivateKeyParameters.InverseQ,
                Modulus = rsaPrivateKeyParameters.Modulus,
                Exponent = rsaPrivateKeyParameters.Exponent,
            };
        }

        internal static RsaPrivateCrtKeyParameters ToRsaPrivateCrtKeyParameters(this RsaPrivateKeyParameters rsaPrivateKeyParameters)
        {
            // ref: https://src-bin.com/en/q/e7ddf
            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rsaPrivateKeyParameters.Modulus),
                new BigInteger(1, rsaPrivateKeyParameters.Exponent),
                new BigInteger(1, rsaPrivateKeyParameters.D),
                new BigInteger(1, rsaPrivateKeyParameters.P),
                new BigInteger(1, rsaPrivateKeyParameters.Q),
                new BigInteger(1, rsaPrivateKeyParameters.DP),
                new BigInteger(1, rsaPrivateKeyParameters.DQ),
                new BigInteger(1, rsaPrivateKeyParameters.InverseQ));
        }
    }
    internal class RsaBcCrypto
    {

        private const string Algorithm = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
        private const string SignatureAlgorithm = "SHA512WITHRSA";
        private const int DefaultRsaBlockSize = 190;

        internal (string privateKeyParametersJson, string publicKeyParametersJson) GenerateKeyPair(int keySize)
        {
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, keySize);
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(keyGenerationParameters);

            var keyPair = generator.GenerateKeyPair();

            var privateKeyParametersJson = JsonConvert.SerializeObject(keyPair.Private.ToPrivateKeyParameters());
            var publicKeyParametersJson = JsonConvert.SerializeObject(keyPair.Public.ToPublicKeyParameters());
            return (privateKeyParametersJson, publicKeyParametersJson);
        }

        internal string Encrypt(string plainText, string publicKeyJson)
        {
            var encryptionKey = JsonConvert.DeserializeObject<RsaPublicKeyParameters>(publicKeyJson).ToRsaKeyParameters();

            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(true, encryptionKey);

            var dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
            var encryptedData = ApplyCipher(dataToEncrypt, cipher, DefaultRsaBlockSize);
            return Convert.ToBase64String(encryptedData);
        }

        internal string Decrypt(string encryptedData, string privateKeyJson)
        {
            var decryptionKey = JsonConvert.DeserializeObject<RsaPrivateKeyParameters>(privateKeyJson).ToRsaPrivateCrtKeyParameters();

            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(false, decryptionKey);

            int blockSize = decryptionKey.Modulus.BitLength / 8;

            var dataToDecrypt = Convert.FromBase64String(encryptedData);
            var decryptedData = ApplyCipher(dataToDecrypt, cipher, blockSize);
            return Encoding.UTF8.GetString(decryptedData);
        }
        internal string SignData(string data, string privateKeyJson)
        {
            var signatureKey = JsonConvert.DeserializeObject<RsaPrivateKeyParameters>(privateKeyJson).ToRsaPrivateCrtKeyParameters();

            var dataToSign = Encoding.UTF8.GetBytes(data);

            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(true, signatureKey);
            signer.BlockUpdate(dataToSign, 0, dataToSign.Length);

            var signature = signer.GenerateSignature();
            return Convert.ToBase64String(signature);
        }
        internal bool VerifySignature(string data, string signature, string publicKeyJson)
        {
            var signatureKey = JsonConvert.DeserializeObject<RsaPublicKeyParameters>(publicKeyJson).ToRsaKeyParameters();

            var dataToVerify = Encoding.UTF8.GetBytes(data);
            var binarySignature = Convert.FromBase64String(signature);

            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(false, signatureKey);
            signer.BlockUpdate(dataToVerify, 0, dataToVerify.Length);

            return signer.VerifySignature(binarySignature);
        }

        private byte[] ApplyCipher(byte[] data, IBufferedCipher cipher, int blockSize)
        {
            var inputStream = new MemoryStream(data);
            var outputBytes = new List<byte>();

            int index;
            var buffer = new byte[blockSize];
            while ((index = inputStream.Read(buffer, 0, blockSize)) > 0)
            {
                var cipherBlock = cipher.DoFinal(buffer, 0, index);
                outputBytes.AddRange(cipherBlock);
            }

            return outputBytes.ToArray();
        }
    }
}
