using Xunit;

namespace ACT_SECURITY_XUNIT_TESTPROJECT
{
    public class HashingTests
    {
   
        public void MD5HASH(string Value)
        {
            Assert.Equal("", ACT.Core.Security.Hashing.MD5Hashing.ToMD5Hash(Value));
        }
    }
}