using System.Security.Cryptography;
using System.Text;
namespace ACT.Core.Security.Identifiers
{
    /// <summary>
    /// Generates Unique Identification code of a computer
    /// TODO Implement Linux and Mac
    /// </summary>
    public static class Machine_Identifier
    {
        private static string _machineidentifier = string.Empty;
        public static string Value()
        {
            if (string.IsNullOrEmpty(_machineidentifier))
            {
                string _tmp = Environment.MachineName + Environment.OSVersion;
                try { _tmp += "CPU >> " + cpuId() + "BIOS >> " + biosId() + "BASE >> " + baseId(); } catch { }
                try { _tmp += "DISK >> " + diskId() + "VIDEO >> " + videoId() + "MAC >> " + macId(); } catch { }

                _machineidentifier = GetHash(_tmp);
            }
            return _machineidentifier;
        }
        private static string GetHash(string s)
        {
            MD5 sec = MD5.Create();

            ASCIIEncoding enc = new ASCIIEncoding();
            byte[] bt = enc.GetBytes(s);
            return GetHexString(sec.ComputeHash(bt));
        }
        private static string GetHexString(byte[] bt)
        {
            string s = string.Empty;
            for (int i = 0; i < bt.Length; i++)
            {
                byte b = bt[i];
                int n, n1, n2;
                n = b;
                n1 = n & 15;
                n2 = (n >> 4) & 15;
                if (n2 > 9)
                {
                    s += ((char)(n2 - 10 + 'A')).ToString();
                }
                else
                {
                    s += n2.ToString();
                }

                if (n1 > 9)
                {
                    s += ((char)(n1 - 10 + 'A')).ToString();
                }
                else
                {
                    s += n1.ToString();
                }

                if ((i + 1) != bt.Length && (i + 1) % 2 == 0)
                {
                    s += "-";
                }
            }
            return s;
        }

        #region Original Device ID Getting Code
        //Return a hardware identifier
        private static string identifier(string wmiClass, string wmiProperty, string wmiMustBeTrue)
        {
            string result = "";

#if WINDOWS
            System.Management.ManagementClass mc = new System.Management.ManagementClass(wmiClass);
            System.Management.ManagementObjectCollection moc = mc.GetInstances();

            foreach (System.Management.ManagementObject mo in moc)
            {
                if (mo[wmiMustBeTrue].ToString() == "True")
                {
                    try
                    {
                        result = mo[wmiProperty].ToString();
                        break;
                    }
                    catch
                    {

                    }
                }
            }
#endif
#if LINUX
            // Add Linux Code in Extensions
#endif
            return result;
        }
        //Return a hardware identifier
        private static string identifier(string wmiClass, string wmiProperty)
        {
            string result = "";
            System.Management.ManagementClass mc = new System.Management.ManagementClass(wmiClass);
            System.Management.ManagementObjectCollection moc = mc.GetInstances();
            foreach (System.Management.ManagementObject mo in moc)
            {

                try
                {
                    result = mo[wmiProperty].ToString();
                    break;
                }
                catch
                {
                }

            }
            return result;
        }
        //CPU Identifier
        private static string cpuId()
        {
            //Uses first CPU identifier available in order of preference
            //Don't get all identifiers, as very time consuming
            string retVal = identifier("Win32_Processor", "UniqueId");
            if (retVal == "") //If no UniqueID, use ProcessorID
            {
                retVal = identifier("Win32_Processor", "ProcessorId");
                if (retVal == "") //If no ProcessorId, use Name
                {
                    retVal = identifier("Win32_Processor", "Name");
                    if (retVal == "") //If no Name, use Manufacturer
                    {
                        retVal = identifier("Win32_Processor", "Manufacturer");
                    }
                    //Add clock speed for extra security
                    retVal += identifier("Win32_Processor", "MaxClockSpeed");
                }
            }
            return retVal;
        }
        //BIOS Identifier
        private static string biosId()
        {
            return identifier("Win32_BIOS", "Manufacturer")
            + identifier("Win32_BIOS", "SMBIOSBIOSVersion")
            + identifier("Win32_BIOS", "IdentificationCode")
            + identifier("Win32_BIOS", "SerialNumber")
            + identifier("Win32_BIOS", "ReleaseDate")
            + identifier("Win32_BIOS", "Version");
        }
        //Main physical hard drive ID
        private static string diskId()
        {
            return identifier("Win32_DiskDrive", "Model")
            + identifier("Win32_DiskDrive", "Manufacturer")
            + identifier("Win32_DiskDrive", "Signature")
            + identifier("Win32_DiskDrive", "TotalHeads");
        }
        //Motherboard ID
        private static string baseId()
        {
            return identifier("Win32_BaseBoard", "Model")
            + identifier("Win32_BaseBoard", "Manufacturer")
            + identifier("Win32_BaseBoard", "Name")
            + identifier("Win32_BaseBoard", "SerialNumber");
        }
        //Primary video controller ID
        private static string videoId()
        {
            return identifier("Win32_VideoController", "DriverVersion")
            + identifier("Win32_VideoController", "Name");
        }
        //First enabled network card ID
        private static string macId()
        {
            return identifier("Win32_NetworkAdapterConfiguration", "MACAddress", "IPEnabled");
        }
        #endregion
    }
}
