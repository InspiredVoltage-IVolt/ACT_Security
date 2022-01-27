/// <summary>
/// ACTLicFileEncryp = Encryption Key For Lic File.
/// </summary>
namespace ACT.SecurityTestConsole // Note: actual namespace depends on the project name.
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var _X = ACT.Core.Security.Encryption.EncryptString("MarkAlicz", "abcdefghijklmnop");
            var _T = ACT.Core.Security.Encryption.DecryptString("MarkAlicz", _X);

            Console.WriteLine(_X);
            Console.WriteLine(_T);
            Console.ReadKey();
        }
    }
}