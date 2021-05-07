
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tpm2Lib;
using TpmStorageHandler;

namespace TpmTest
{
    [TestClass]
    public class UnitTest1
    {
        private static (TpmPublic pubKey, TpmHandle handle) GeneratePublicKey(Tpm2Wrapper tpm)
        {
            TpmHandle handle = tpm.CreateRsaPrimaryStorageKey(out TpmPublic pubKey);
            return (pubKey, handle);
        }

        [TestMethod]
        public void TestKeyCreation()
        {
            (TpmPublic pubKey, TpmHandle handle) result;
            using (Tpm2Wrapper tpm = new Tpm2Wrapper())
            {
                AuthValue auth = AuthValue.FromRandom(8);
                result = GeneratePublicKey(tpm);
            }
            Assert.IsNotNull(result.pubKey);
        }
    }
}
