using ACT.Core.Security;
using ACT.Core.Security.Encryption;
using SECInt = ACT.Core.Interfaces.Security;

namespace ACT.Core.Extensions
{
    public static class EncryptionExtensions
    {
        private static SECInt.I_Encryption _EncryptionClass = null;

        public static string EncryptString(this string StringToEncrypt, string Password)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.Encrypt(StringToEncrypt, Password);
        }

        public static string DecryptString(this string StringToDecrypt, string Password)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.Decrypt(StringToDecrypt, Password);
        }

        public static bool EncryptFile(this string FullFilePathToEncrypt, string OutputFileFullPath, string Password, bool DeleteOriginal = false)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            try
            {
                _EncryptionClass.Encrypt(FullFilePathToEncrypt, OutputFileFullPath, Password);
                if (DeleteOriginal) { FullFilePathToEncrypt.DeleteFile(25, true); }
                return true;
            }
            catch (Exception ex)
            {
                throw new Exception("Error Decrypting File: " + ex.Message, ex);
            }
        }

        public static bool DecryptFile(this string FullFilePathToDecrypt, string OutputFileFullPath, string Password, bool DeleteOriginal = false)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            try
            {
                _EncryptionClass.Decrypt(FullFilePathToDecrypt, OutputFileFullPath, Password);
                if (DeleteOriginal) { FullFilePathToDecrypt.DeleteFile(25, true); }
                return true;
            }
            catch (Exception ex)
            {
                throw new Exception("Error Decrypting File: " + ex.Message, ex);
            }
        }


        public static byte[] EncrypByteArray(this byte[] DataToEncrypt, string Password)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.Encrypt(DataToEncrypt, Password);
        }

        public static byte[] DecryptByteArray(this byte[] DataToDecrypt, string Password)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.Decrypt(DataToDecrypt, Password);
        }

        /// <summary>
        /// Protect Data using Microsofts Protect Data Class.
        /// </summary>
        /// <param name="DataToProtect">string Of Data To Protect</param>
        /// <param name="MachineLevel">True / False</param>
        /// <returns></returns>
        public static string ProtectData(this string DataToProtect, bool MachineLevel = true)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.NarrowEncrypt(DataToProtect,!MachineLevel,MachineLevel);
        }

        /// <summary>
        /// Un Protect Data Using The Microsoft Protect Data Class
        /// </summary>
        /// <param name="DataToUnProtect">String Of Data To UnProtect</param>
        /// <param name="MachineLevel">True / False</param>
        /// <returns></returns>
        public static string UnProtectData(this string DataToUnProtect, bool MachineLevel = true)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.NarrowDecrypt(DataToUnProtect, !MachineLevel, MachineLevel);
        }

        public static string ToSHA256(this string DataToHash)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.SHA256(DataToHash);
        }

        public static string ToSHA512(this string DataToHash)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.SHA512(DataToHash);
        }

        public static string ToMD5(this string DataToHash)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.MD5(DataToHash);
        }

        public static string ToMD5_ALT(this string DataToHash)
        {
            if (_EncryptionClass == null) { _EncryptionClass = ACT_Security_Core.GetEncryptionClass("ACT", ""); }
            return _EncryptionClass.MD5ALT(DataToHash);
        }        
    }

}

