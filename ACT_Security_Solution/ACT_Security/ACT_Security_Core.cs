using ACT.Core.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ACT.Core.Security
{
    public static class ACT_Security_Core
    {
        
        private static string _MachineKey = "aab6a66eb993431da054cdecd48c781c5f5afcdf6e3e4ef18d9c9016da5dc555c17e877b9a254a3f81914e2f330596fb234d7ea934214a75834a0dccb9b12fb7";
        private static Interfaces.Security.I_Encryption LoadedEncryptionClass = null;
        private static List<string> _ImplementationsAvailable = new List<string>() { "ACT.Core.Security.Encryption.ACTEncryption" };

        /// <summary>
        /// Gets the Encryption Module Based On the Name,  Currently Only ACT works.
        /// </summary>
        /// <param name="ClassName">Name of the Custom Module</param>
        /// <param name="SecurityMixer">OPTIONAL Security Entropy</param>
        /// <returns><seealso cref="ACT.Core.Interfaces.Security.I_Encryption">I_Encryption Class</seealso>/></returns>
        public static Interfaces.Security.I_Encryption GetEncryptionClass(string ClassName, string SecurityMixer = "")
        {
            if (SecurityMixer.NullOrEmpty() == false && SecurityMixer.Length < 5)
            {
                SecurityMixer = _MachineKey;
            }

            if (ClassName == "ACT")
            {
                LoadedEncryptionClass = new Encryption.ACTEncryption(SecurityMixer);
            }
            else
            {
                LoadedEncryptionClass = new Encryption.ACTEncryption(SecurityMixer);
            }
            // TODO ADD DIFFERENT MODULES

            return LoadedEncryptionClass;
        }

        public static List<string> GetCurrent_I_Encryption_Implementations
        {
            get
            {
                return _ImplementationsAvailable;
            }
        }
    }
}
