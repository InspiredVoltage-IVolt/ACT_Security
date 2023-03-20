using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ACT.Core.Extensions;
namespace ACT
{
   public static class _S
   {
      public static bool IsBinaryFile(string path) { return path.IsBinaryFile(); }

      public static string ProtectFile(string FileToProtect, bool MachineLevel = true, bool BackupFile = true) { return ACT.Core.Security.ProtectData.Protect(FileToProtect, MachineLevel, BackupFile); }
      public static string ProtectImportantFile(string FileToProtect, bool MachineLevel = true, bool BackupFile = true) { return ACT.Core.Security.ProtectData.Protect(FileToProtect,MachineLevel, BackupFile); }


   }
}
