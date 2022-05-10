using ACT.Core.Extensions;
using System.Security.Cryptography;

namespace ACT.Core.Security.Hashing
{
    public static class MD5Hashing
    {
        /// <summary>
        /// Convert a input string to a byte array and compute the hash.  ALWAYS USES TO UPPER
        /// </summary>
        /// <param name="value">Input string.</param>
        /// <returns>The Hexadecimal string.</returns>
        public static string ToMD5Hash(this string value, bool removeDashes = false)
        {
            return ACT_Core_Security.GetBase64StringFromByteArray(System.Text.Encoding.UTF8.GetBytes(value),removeDashes);            
        }
    }
}

/*
// OLD CODE
 using (MD5 md5 = MD5.Create())
{
    var originalBytes = System.Text.Encoding.UTF8.GetBytes(value);
    var encodedBytes = md5.ComputeHash(originalBytes);

    if (removeDashes) { return Convert.ToBase64String(encodedBytes).Replace("-", ""); }
    else { return Convert.ToBase64String(encodedBytes); }
}
 */