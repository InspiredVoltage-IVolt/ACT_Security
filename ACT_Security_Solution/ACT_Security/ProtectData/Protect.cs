using ACT.Core.Extensions;
using System.Security.Cryptography;

namespace ACT.Core.Security
{
#pragma warning disable CA1416 // Validate platform compatibility
    public static class ProtectData
    {
        /// <summary>
        /// Be Careful Not Fully Tested
        /// </summary>
        /// <param name="DataToProtect"></param>
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static byte[] ProtectStringUsingMachineEntropy(string DataToProtect, bool MachineLevel = true)
        {
            byte[] _Entropy = Identifiers.Machine_Identifier.Value().ToBytes();
            if (MachineLevel)
            {
                return ProtectedData.Protect(DataToProtect.ObjectToByteArray(), _Entropy, DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Protect(DataToProtect.ObjectToByteArray(), _Entropy, DataProtectionScope.CurrentUser);
            }
        }

        /// <summary>
        /// Be Careful Not Fully Tested
        /// </summary>
        /// <param name="DataToProtect"></param>
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static byte[] UnProtectStringUsingMachineEntropy(string DataToProtect, bool MachineLevel = true)
        {
            byte[] _Entropy = Identifiers.Machine_Identifier.Value().ToBytes();
            if (MachineLevel)
            {
                return ProtectedData.Unprotect(DataToProtect.ObjectToByteArray(), _Entropy, DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Unprotect(DataToProtect.ObjectToByteArray(), _Entropy, DataProtectionScope.CurrentUser);
            }
        }

        /// <summary>
        /// Protect a String
        /// </summary>
        /// <param name="DataToProtect"></param>
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static byte[] ProtectString(string DataToProtect, bool MachineLevel = true)
        {
            if (MachineLevel)
            {
                return ProtectedData.Protect(DataToProtect.ObjectToByteArray(), null, DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Protect(DataToProtect.ObjectToByteArray(), null, DataProtectionScope.CurrentUser);
            }
        }

        /// <summary>
        /// Unprotect a String
        /// </summary>
        /// <param name="DataToProtect"></param>
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static byte[] UnProtectString(string DataToProtect, bool MachineLevel = true)
        {
            if (MachineLevel)
            {
                return ProtectedData.Unprotect(DataToProtect.ObjectToByteArray(), null, DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Unprotect(DataToProtect.ObjectToByteArray(), null, DataProtectionScope.CurrentUser);
            }
        }

        /// <summary>
        /// Protect a String
        /// </summary>
        /// <param name="DataToProtect"></param>
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static string ProtectStringToString(string DataToProtect, bool MachineLevel = true)
        {
            if (MachineLevel)
            {
                return ProtectedData.Protect(DataToProtect.ObjectToByteArray(), null, DataProtectionScope.LocalMachine).ToBase64String();
            }
            else
            {
                return ProtectedData.Protect(DataToProtect.ObjectToByteArray(), null, DataProtectionScope.CurrentUser).ToBase64String();
            }
        }

        /// <summary>
        /// Unprotect a String
        /// </summary>
        /// <param name="DataToProtect"></param>
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static string UnProtectStringToString(string DataToProtect, bool MachineLevel = true)
        {
            if (MachineLevel)
            {
                return System.Text.Encoding.Default.GetString(ProtectedData.Unprotect(DataToProtect.FromBase64String(), null, DataProtectionScope.LocalMachine));
            }
            else
            {
                return System.Text.Encoding.Default.GetString(ProtectedData.Unprotect(DataToProtect.FromBase64String(), null, DataProtectionScope.CurrentUser));
            }
        }

    }
#pragma warning restore CA1416 // Validate platform compatibility
}
