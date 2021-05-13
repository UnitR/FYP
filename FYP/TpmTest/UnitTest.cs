
using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tpm2Lib;
using TpmStorageHandler;
using Newtonsoft.Json;
using System.IO;
using Windows.UI.Xaml;
using Windows.Storage;
using TpmStorageHandler.Structures;

namespace TpmTest
{
    [TestClass]
    public class UnitTest1
    {

        private const string TEST_MESSAGE = "ABCD";

        private static KeyWrapper GeneratePrimaryKey(Tpm2Wrapper tpm)
        {
            TpmHandle handle = tpm.CreateRsaPrimaryStorageKey(out TpmPublic pubKey);
            return new KeyWrapper(handle, pubKey);
        }

        private static KeyWrapper GenerateChildKey(TpmHandle primHandle, Tpm2Wrapper tpm)
            => tpm.CreateChildKey(primHandle);

        private static void CleanUp(Tpm2Wrapper tpm, TpmHandle[] contexts)
        {
            foreach (TpmHandle context in contexts)
            {
                tpm.FlushContext(context);
            }
            tpm.Dispose();
        }

        [TestMethod]
        public void TestPrimaryKeyCreation()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper result = GeneratePrimaryKey(tpm);
            
            Assert.IsNotNull(result.KeyPub);

            CleanUp(tpm, new TpmHandle[] {result.Handle});
        }

        [TestMethod]
        public void TestChildKeyCreation()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = tpm.CreateChildKey(primKey.Handle);

            Assert.IsNotNull(childKey.KeyPub);

            CleanUp(tpm, new TpmHandle[] {primKey.Handle, childKey.Handle});
        }

        [TestMethod]
        public void TestEncrypt()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = GenerateChildKey(primKey.Handle, tpm);

            string expected = "abcd";
            byte[] encMessage = tpm.Encrypt(expected, childKey, out byte[] iv);

            Assert.IsNotNull(encMessage);

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }

        [TestMethod]
        public void TestEncryptDecryptMessage()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = GenerateChildKey(primKey.Handle, tpm);

            string expected = "abcd";

            byte[] encMessage = tpm.Encrypt(expected, childKey, out byte[] iv);
            byte[] decMessage = tpm.Decrypt(encMessage, childKey, iv);
            string result = Encoding.UTF8.GetString(decMessage);

            Assert.AreEqual(expected, result);

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }

        [TestMethod]
        public void TestSaveDuplicate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = GenerateChildKey(primKey.Handle, tpm);

            // Duplicate child key
            KeyDuplicate childDupe = tpm.DuplicateChildKey(childKey, primKey.Handle);

            // Encrypt the key provided by the duplication
            byte[] dupeKeyEncrypted = tpm.Encrypt(childDupe.EncKeyOut, primKey, out byte[] iv);

            // Store this in an object
            FileEncryptionData fed = new FileEncryptionData(null, childDupe.Duplicate.buffer, iv, dupeKeyEncrypted, childDupe.Seed);
            string fedJson = JsonConvert.SerializeObject(fed);

            // Save data on disk
            System.IO.File.WriteAllText(@".\fileEnc.secure", fedJson);

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }

        [TestMethod]
        public void TestEncryptChildKeyPrivate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = GenerateChildKey(primKey.Handle, tpm);

            // Encrypt a message to decrypt later
            byte[] encMessage = tpm.Encrypt(TEST_MESSAGE, childKey, out byte[] encIv);

            // Encrypt child key using the primary key
            byte[] childKeyEncrypted = tpm.RsaEncrypt(primKey, childKey.KeyPriv);

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

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }

        [TestMethod]
        public void TestLoadChildKeyFromFile()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);

            StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
            StorageFile fedFile = storageFolder.GetFileAsync("test.txt").GetAwaiter().GetResult();
            string fedJson = FileIO.ReadTextAsync(fedFile).GetAwaiter().GetResult();

            FileEncryptionData fed = JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);
            byte[] keyPrivate = tpm.RsaDecrypt(primKey, fed?.TpmPrivateArea);

            KeyWrapper childKey = tpm.LoadChildKeyExternal(keyPrivate, primKey);
            byte[] resultMessage = tpm.Decrypt(fed?.FileData, childKey, fed?.EncryptionIv);

            Assert.AreEqual(Encoding.UTF8.GetString(resultMessage), TEST_MESSAGE);

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }
    }
}