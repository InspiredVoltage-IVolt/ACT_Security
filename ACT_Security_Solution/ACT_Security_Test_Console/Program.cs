using ACT.Core.Security.Hashing;

/// <summary>
/// ACTLicFileEncryp = Encryption Key For Lic File.
/// </summary>
namespace ACT.SecurityTestConsole // Note: actual namespace depends on the project name.
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("inVKr945".ToMD5Hash(true));
            Console.WriteLine(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("55011c74283004471847ee1b2166bf0e")));
            Console.ReadKey();

          
        }
    }
}