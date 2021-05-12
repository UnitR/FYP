
using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tpm2Lib;
using TpmStorageHandler;
using Newtonsoft.Json;
using System.IO;
using Windows.UI.Xaml;
using Windows.Storage;

namespace TpmTest
{
    [TestClass]
    public class UnitTest1
    {

        private const string TEST_MESSAGE = "ABCD";

        private static Tpm2Wrapper.KeyWrapper GeneratePrimaryKey(Tpm2Wrapper tpm)
        {
            TpmHandle handle = tpm.CreateRsaPrimaryStorageKey(out TpmPublic pubKey);
            return new Tpm2Wrapper.KeyWrapper(handle, pubKey);
        }

        private static Tpm2Wrapper.KeyWrapper GenerateChildKey(TpmHandle primHandle, Tpm2Wrapper tpm)
            => tpm.CreateChildKey(primHandle);

        [TestMethod]
        public void TestPrimaryKeyCreation()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper result = GeneratePrimaryKey(tpm);
            
            Assert.IsNotNull(result.keyPub);

            tpm.FlushContext(result.handle);
            tpm.Dispose();
        }

        [TestMethod]
        public void TestChildKeyCreation()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);
            Tpm2Wrapper.KeyWrapper childKey = tpm.CreateChildKey(primKey.handle);

            Assert.IsNotNull(childKey.keyPub);

            tpm.FlushContext(primKey.handle);
            tpm.FlushContext(childKey.handle);

            tpm.Dispose();
        }

        [TestMethod]
        public void TestEncrypt()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);
            Tpm2Wrapper.KeyWrapper childKey = GenerateChildKey(primKey.handle, tpm);

            string expected = "abcd";
            byte[] encMessage = tpm.Encrypt(expected, childKey, out byte[] iv);

            Assert.IsNotNull(encMessage);

            tpm.FlushContext(primKey.handle);
            tpm.FlushContext(childKey.handle);
            tpm.Dispose();
        }

        [TestMethod]
        public void TestEncryptDecryptMessage()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);
            Tpm2Wrapper.KeyWrapper childKey = GenerateChildKey(primKey.handle, tpm);

            string expected = "abcd";

            byte[] encMessage = tpm.Encrypt(expected, childKey, out byte[] iv);
            byte[] decMessage = tpm.Decrypt(encMessage, childKey, iv);
            string result = Encoding.UTF8.GetString(decMessage);

            Assert.AreEqual(expected, result);

            tpm.FlushContext(primKey.handle);
            tpm.FlushContext(childKey.handle);
            tpm.Dispose();
        }

        [TestMethod]
        public void TestSaveDuplicate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);
            Tpm2Wrapper.KeyWrapper childKey = GenerateChildKey(primKey.handle, tpm);

            // Duplicate child key
            Tpm2Wrapper.KeyDuplicate childDupe = tpm.DuplicateChildKey(childKey, primKey.handle);

            // Encrypt the key provided by the duplication
            byte[] dupeKeyEncrypted = tpm.Encrypt(childDupe.encKeyOut, primKey, out byte[] iv);

            // Store this in an object
            FileEncryptionData fed = new FileEncryptionData(null, childDupe.duplicate.buffer, iv, dupeKeyEncrypted, childDupe.seed);
            string fedJson = JsonConvert.SerializeObject(fed);

            // Save data on disk
            System.IO.File.WriteAllText(@".\fileEnc.secure", fedJson);
        }

        [TestMethod]
        public void TestEncryptChildKeyPrivate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);
            Tpm2Wrapper.KeyWrapper childkey = GenerateChildKey(primKey.handle, tpm);

            // Encrypt a message to decrypt later
            byte[] encMessage = tpm.Encrypt(TEST_MESSAGE, childkey, out byte[] encIv);

            // Encrypt child key using the primary key
            byte[] childKeyEncrypted = tpm.RsaEncrypt(primKey, childkey.keyPriv);

            // Store this in an object
            FileEncryptionData fed = new FileEncryptionData(encMessage, childKeyEncrypted, encIv, null, null);
            string fedJson = JsonConvert.SerializeObject(fed);

            // Save data on disk
            Windows.Storage.StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
            StorageFile file = 
                storageFolder.CreateFileAsync(
                    "test.txt",
                    Windows.Storage.CreationCollisionOption.ReplaceExisting).GetAwaiter().GetResult();
            FileIO.WriteTextAsync(file, fedJson).GetAwaiter().GetResult();
        }

        [TestMethod]
        public void TestLoadChildKeyFromFile()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);

            StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
            StorageFile fedFile = storageFolder.GetFileAsync("test.txt").GetAwaiter().GetResult();
            string fedJson = FileIO.ReadTextAsync(fedFile).GetAwaiter().GetResult();

            FileEncryptionData fed = JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);
            byte[] keyPrivate = tpm.RsaDecrypt(primKey, fed?.TpmPrivateArea);

            Tpm2Wrapper.KeyWrapper childKey = tpm.LoadChildKeyExternal(keyPrivate, primKey);
            byte[] resultMessage = tpm.Decrypt(fed?.FileData, childKey, fed?.EncryptionIv);

            Assert.AreEqual(Encoding.UTF8.GetString(resultMessage), TEST_MESSAGE);
        }

        [TestMethod]
        public void TestCreatePrimaryWithParent()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            Tpm2Wrapper.KeyWrapper primKey = GeneratePrimaryKey(tpm);
            Tpm2Wrapper.KeyWrapper primChildKey = tpm.CreateNewPrimaryKeyWithParent(primKey.handle);

            Assert.IsNotNull(primChildKey.handle);

            tpm.FlushContext(primKey.handle);
            tpm.FlushContext(primChildKey.handle);
            tpm.Dispose();
        }
    }
}