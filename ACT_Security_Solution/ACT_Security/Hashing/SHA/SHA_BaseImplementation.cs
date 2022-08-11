using ACT.Core.Extensions;
using System.Security.Cryptography;

namespace ACT.Core.Security.Hashing
{
    /// <summary>
    /// SHA Hashing Class
    /// </summary>
    public static class SHAHashing
    {

        /// <summary>
        /// Convert a input string to a byte array and compute the hash.
        /// </summary>
        /// <param name="value">Input string.</param>
        /// <returns>The Hexadecimal string.</returns>
        public static string StringToSHA256Hash(string value, bool removeDashes = true)
        {
            if (value.NullOrEmpty())
            {
                return value.ToString(true);
            }

            using (var hasher = SHA256.Create())
            {
                var originalBytes = System.Text.Encoding.UTF8.GetBytes(value);
                var encodedBytes = hasher.ComputeHash(originalBytes);
                string _tmpReturn = "";
                if (removeDashes) { _tmpReturn = BitConverter.ToString(encodedBytes).Replace("-", string.Empty).ToUpper(); }
                else { _tmpReturn = BitConverter.ToString(encodedBytes); }

                return _tmpReturn;
            }
        }

        /// <summary>
        /// Convert a input string to a byte array and compute the hash.
        /// </summary>
        /// <param name="value">Input string.</param>
        /// <returns>The Hexadecimal string.</returns>
        public static string ToSHA512Hash(string value, bool removeDashes = true)
        {
            if (value.NullOrEmpty())
            {
                return value.ToString(true);
            }

            using (var hasher = SHA512.Create())
            {
                var originalBytes = System.Text.Encoding.UTF8.GetBytes(value);
                var encodedBytes = hasher.ComputeHash(originalBytes);
                string _tmpReturn = "";
                if (removeDashes) { _tmpReturn = BitConverter.ToString(encodedBytes).Replace("-", string.Empty).ToUpper(); }
                else { _tmpReturn = BitConverter.ToString(encodedBytes); }

                return _tmpReturn;
            }
        }


        /// <summary>
        /// Convert a input string to a byte array and compute the hash.
        /// </summary>
        /// <param name="value">Input string.</param>
        /// <returns>The Hexadecimal string.</returns>
        public static string ToSHA256Hash(string value, bool removeDashes = true)
        {
            if (value.NullOrEmpty())
            {
                return value.ToString(true);
            }

            using (var hasher = SHA256.Create())
            {
                var originalBytes = System.Text.Encoding.UTF8.GetBytes(value);
                var encodedBytes = hasher.ComputeHash(originalBytes);
                string _tmpReturn = "";
                if (removeDashes) { _tmpReturn = BitConverter.ToString(encodedBytes).Replace("-", string.Empty).ToUpper(); }
                else { _tmpReturn = BitConverter.ToString(encodedBytes); }

                return _tmpReturn;
            }
        }
    }
}


