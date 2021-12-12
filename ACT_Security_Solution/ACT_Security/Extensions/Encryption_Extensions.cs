using ACT.Core.Security;


namespace ACT.Core.Extensions
{
    public static class EncryptionExtensions
    {
        public static string EncryptString(this string StringToEncrypt, string Password)
        {
            return Encryption.EncryptString(StringToEncrypt, Password);
        }

        public static string DecryptString(this string StringToDecrypt, string Password)
        {
            return Encryption.DecryptString(StringToDecrypt, Password);
        }
    }

}

