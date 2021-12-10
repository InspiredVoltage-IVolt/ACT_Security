using ACT.Core.Security.Hashing;


namespace ACT.Core.Extensions
{
    public static class SHAExtensions
    {
        public static string ToSHA256Hash(this string valueToHash, bool removeDashes = true)
        {
            return SHAHashing.ToSHA256Hash(valueToHash, removeDashes);
        }

        public static string ToSHA512Hash(this string valueToHash, bool removeDashes = true)
        {
            return SHAHashing.ToSHA512Hash(valueToHash, removeDashes);
        }
    }

    public static class MD5Extensions
    {
        public static string ToMD5Hash(this string valueToHash, bool removeDashes = true)
        {
            return MD5Hashing.ToMD5Hash(valueToHash, removeDashes);
        }
    }
}

