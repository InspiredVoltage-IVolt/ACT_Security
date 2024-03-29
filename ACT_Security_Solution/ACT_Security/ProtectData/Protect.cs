﻿using ACT.Core.Extensions;
using System.Security.Cryptography;
using System.Text;
using DeviceId;

namespace ACT.Core.Security
{
#pragma warning disable CA1416 // Validate platform compatibility
    public static class ProtectData
    {
      /// <summary>
      /// Protect File
      /// </summary>
      /// <param name="FileToProtect"></param>
      /// <param name="MachineLevel"></param>
      /// <returns></returns>
      public static string Protect(string FileToProtect, bool MachineLevel = true, bool BackupFile=true)
      {
         if (FileToProtect.FileExists() == false) { throw new FileNotFoundException("File: " + FileToProtect + " Does Not Exist", FileToProtect); }

         bool BinaryFile = FileToProtect.IsBinaryFile();
         string _FileToProtect = FileToProtect; 

         if (MachineLevel)
         {
            if (BinaryFile)
            {
               byte[] _ProtectedData = Security.ProtectData.Protect(System.IO.File.ReadAllBytes(FileToProtect), true);
               FileToProtect = FileToProtect.Replace(FileToProtect.GetExtensionFromFileName().Trim("."), ".enc");
               System.IO.File.WriteAllText(FileToProtect, System.Text.Encoding.UTF8.GetString(_ProtectedData));
               System.IO.File.Delete(_FileToProtect);
            }
            else
            {
               byte[] _ProtectedData = Security.ProtectData.Protect(System.Text.Encoding.UTF8.GetBytes(FileToProtect.ReadAllText()), true);
               FileToProtect = FileToProtect.Replace(FileToProtect.GetExtensionFromFileName().Trim("."), ".enc");
               System.IO.File.WriteAllText(FileToProtect, System.Text.Encoding.UTF8.GetString(_ProtectedData));
               System.IO.File.Delete(_FileToProtect);
            }
         }
         else
         {
            if (BinaryFile)
            {
               byte[] _ProtectedData = Security.ProtectData.Protect(System.IO.File.ReadAllBytes(FileToProtect), false);
               FileToProtect = FileToProtect.Replace(FileToProtect.GetExtensionFromFileName().Trim("."), ".enc");
               System.IO.File.WriteAllText(FileToProtect, System.Text.Encoding.UTF8.GetString(_ProtectedData));
               System.IO.File.Delete(_FileToProtect);
            }
            else
            {
               byte[] _ProtectedData = Security.ProtectData.Protect(System.Text.Encoding.UTF8.GetBytes(FileToProtect.ReadAllText()), false);
               FileToProtect = FileToProtect.Replace(FileToProtect.GetExtensionFromFileName().Trim("."), ".enc");
               System.IO.File.WriteAllText(FileToProtect, System.Text.Encoding.UTF8.GetString(_ProtectedData));
               System.IO.File.Delete(_FileToProtect);
            }
         }

         if (BackupFile)
         {
            System.IO.File.Copy(_FileToProtect, Protect(_FileToProtect + ".bak", true));
         }
         
         _FileToProtect.DeleteFile(2000);

         return FileToProtect;
      }


      /// <summary>
      /// Protect a String
      /// </summary>
      /// <param name="DataToProtect"></param>
      /// <param name="MachineLevel"></param>
      /// <returns></returns>
      public static byte[] Protect(byte[] DataToProtect, bool MachineLevel = true)
	    {
		    if (MachineLevel)
		    {
			    return ProtectedData.Protect(DataToProtect, null, DataProtectionScope.LocalMachine);
		    }
		    else
		    {
			    return ProtectedData.Protect(DataToProtect, null, DataProtectionScope.CurrentUser);
		    }
	    }
	    /// <summary>
	    /// Unprotect a Byte[]
	    /// </summary>
	    /// <param name="DataToProtect"></param>
	    /// <param name="MachineLevel"></param>
	    /// <returns></returns>
	    public static byte[] UnProtect(byte[] DataToProtect, bool MachineLevel = true)
	    {
		    if (MachineLevel)
		    {
			    return ProtectedData.Unprotect(DataToProtect, null, DataProtectionScope.LocalMachine);
		    }
		    else
		    {
			    return ProtectedData.Unprotect(DataToProtect, null, DataProtectionScope.CurrentUser);
		    }
	    }


        public static string GetCommonWindowsEntropy()
        {
            string x = Environment.GetEnvironmentVariable("windir");
            if (x == null)
            {
                // TODO Add KLogger
                throw new Exception("Error: BAD Code. Contact Admin.");
            }

            x = x.EnsureDirectoryFormat();
            var _ByteData = System.IO.File.ReadAllBytes(x += "RegEdit.exe");
            FileInfo _FI = new FileInfo(x);
           
            var _TData = Encoding.UTF8.GetString(_ByteData);

            return _TData.Substring(0,200);

        }
        /// <summary>
        /// Be Careful Not Fully Tested
        /// </summary>                                 
        /// <param name="DataToProtect"></param>                                       
        /// <param name="MachineLevel"></param>
        /// <returns></returns>
        public static byte[] ProtectStringUsingMachineEntropy(string DataToProtect, bool MachineLevel = true)
        {
	        if (MachineLevel)
            {
                return ProtectedData.Protect(Encoding.UTF8.GetBytes(DataToProtect), Encoding.UTF8.GetBytes(GetCommonWindowsEntropy()), DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Protect(Encoding.UTF8.GetBytes(DataToProtect), Encoding.UTF8.GetBytes(GetCommonWindowsEntropy()), DataProtectionScope.CurrentUser);
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
            if (MachineLevel)
            {
                return ProtectedData.Unprotect(Encoding.UTF8.GetBytes(DataToProtect), Encoding.UTF8.GetBytes(GetCommonWindowsEntropy()), DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Unprotect(Encoding.UTF8.GetBytes(DataToProtect), Encoding.UTF8.GetBytes(GetCommonWindowsEntropy()), DataProtectionScope.CurrentUser);
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
                return ProtectedData.Protect(Encoding.UTF8.GetBytes (DataToProtect), null, DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Protect(Encoding.UTF8.GetBytes(DataToProtect), null, DataProtectionScope.CurrentUser);
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
                return ProtectedData.Unprotect(Encoding.UTF8.GetBytes(DataToProtect), null, DataProtectionScope.LocalMachine);
            }
            else
            {
                return ProtectedData.Unprotect(Encoding.UTF8.GetBytes(DataToProtect), null, DataProtectionScope.CurrentUser);
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
                return System.Text.Encoding.UTF8.GetString(ProtectedData.Unprotect(DataToProtect.FromBase64String(), null, DataProtectionScope.LocalMachine));
            }
            else
            {
                return System.Text.Encoding.UTF8.GetString(ProtectedData.Unprotect(DataToProtect.FromBase64String(), null, DataProtectionScope.CurrentUser));
            }
        }

    }
#pragma warning restore CA1416 // Validate platform compatibility
}
