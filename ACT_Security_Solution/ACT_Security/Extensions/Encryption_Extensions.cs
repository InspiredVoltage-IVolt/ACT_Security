using ACT.Core.Security;


namespace ACT.Core.Extensions
{
    public static class EncryptionExtensions
    {
        public static string EncryptString(this string valueToHash, string Password)
        {
            return Encryption.EncryptString(valueToHash, Password);
        }

        public static string DecryptString(this string valueToHash, string Password)
        {
            return Encryption.DecryptString(valueToHash, Password);
        }
    }

}

