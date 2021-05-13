
using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tpm2Lib;
using TpmStorageHandler;
using Newtonsoft.Json;
using System.IO;
using Windows.UI.Xaml;
using Windows.Storage;
using Windows.UI.WebUI;
using TpmStorageHandler.Structures;

namespace TpmTest
{
    [TestClass]
    public class UnitTest1
    {
        private const string _dupekeyFileName = "dupeKey.secure";

        private const string TEST_MESSAGE = "ABCD";

        private static KeyWrapper GeneratePrimaryKey(Tpm2Wrapper tpm)
        {
            TpmHandle handle = tpm.CreatePrimaryStorageKey(out TpmPublic pubKey);
            return new KeyWrapper(handle, pubKey);
        }

        private static KeyWrapper GenerateChildKey(TpmHandle primHandle, Tpm2Wrapper tpm, byte[] authSession = null)
            => tpm.CreateChildKey(primHandle, authSession);

        private static void SaveFile(string fileName, string fileData, out StorageFile file)
        {
            Windows.Storage.StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
            file = storageFolder.CreateFileAsync(
                fileName,
                Windows.Storage.CreationCollisionOption.ReplaceExisting).GetAwaiter().GetResult();
            FileIO.WriteTextAsync(file, fileData).GetAwaiter().GetResult();
        }

        private static string LoadFile(string fileName)
        {
            StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
            StorageFile file = storageFolder
                .GetFileAsync(fileName).GetAwaiter().GetResult();
            return FileIO.ReadTextAsync(file).GetAwaiter().GetResult();
        }

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
            byte[] encMessage = tpm.Encrypt(Encoding.UTF8.GetBytes(expected), childKey, out byte[] iv);

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

            byte[] encMessage = tpm.Encrypt(Encoding.UTF8.GetBytes(expected), childKey, out byte[] iv);
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

            // Need to ensure we have a session for verifying the key creation
            PolicySession dupeSession = tpm.StartDuplicatePolicySession();
            KeyWrapper childKey = GenerateChildKey(primKey.Handle, tpm, dupeSession.PolicyHash);

            // Private child key. Use the same session the key was created under.
            KeyDuplicate childDupe = tpm.DuplicateChildKey(childKey, primKey, dupeSession);

            // No longer need the duplicate session
            tpm.FlushContext(dupeSession.AuthSession);

            // Start an encrypt/decrypt session
            PolicySession encDecSession = tpm.StartEncryptDecryptPolicySession();

            // Also encrypt a test message
            byte[] encMessage = tpm.Encrypt(
                Encoding.UTF8.GetBytes(TEST_MESSAGE),
                childKey, 
                null,
                out byte[] encryptionIv);

            // Flush the encrypt session
            tpm.FlushContext(encDecSession.AuthSession);

            // Store this in an object
            byte[] childPublic = childDupe.Public.GetTpmRepresentation();
            byte[] childPrivate = childDupe.Private.GetTpmRepresentation();
            
            // Create a data structure containing all necessary data
            FileEncryptionData fed = new FileEncryptionData(
                encMessage, childPrivate, childPublic, dupeSession.PolicyHash, 
                childDupe.EncKey, childDupe.Seed, encryptionIv);
            string fedJson = JsonConvert.SerializeObject(fed);

            // Save data on disk
            SaveFile(_dupekeyFileName, fedJson, out StorageFile _);

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }

        [TestMethod]
        public void TestLoadDuplicate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);

            string fedJson = LoadFile(_dupekeyFileName);
            FileEncryptionData fed = 
                JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);

            // File should not be empty
            Assert.IsNotNull(fed);
            
            KeyDuplicate keyDupe = new KeyDuplicate(
                fed.EncryptionKey,
                fed.EncryptionSeed,
                fed.PrivateArea,
                fed.PublicArea);
            KeyWrapper childKey = tpm.ImportKey(primKey.Handle, keyDupe);

            // Test to see if the key was loaded
            Assert.IsNotNull(childKey.Handle);

            // Try decrypting the previously encrypted test message
            PolicySession encDecSession = tpm.StartEncryptDecryptPolicySession();
            byte[] decMessage = tpm.Decrypt(
                fed.FileData,
                childKey,
                null,
                fed.EncryptionIv);

            // Flush the decrypt session
            tpm.FlushContext(encDecSession.AuthSession);

            // And then check equality
            Assert.Equals(TEST_MESSAGE, Encoding.UTF8.GetString(decMessage));

            CleanUp(tpm, new TpmHandle[] {primKey.Handle, childKey.Handle});
        }

        [TestMethod]
        public void TestEncryptChildKeyPrivate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = GenerateChildKey(primKey.Handle, tpm);

            // Encrypt a message to decrypt later
            byte[] encMessage = tpm.Encrypt(
                Encoding.UTF8.GetBytes(TEST_MESSAGE), childKey, out byte[] encIv);

            // Encrypt child key using the primary key
            byte[] childKeyEncrypted = tpm.RsaEncrypt(primKey, childKey.KeyPriv);

            // Store this in an object
            FileEncryptionData fed = new FileEncryptionData(encMessage, childKeyEncrypted, null, null, encIv);
            string fedJson = JsonConvert.SerializeObject(fed);

            //SaveFile(fedJson, out var file);

            CleanUp(tpm, new TpmHandle[] { primKey.Handle, childKey.Handle });
        }
    }
}