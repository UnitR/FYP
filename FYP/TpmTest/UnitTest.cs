
using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tpm2Lib;
using TpmStorageHandler;
using Newtonsoft.Json;
using System.IO;
using System.Linq;
using Windows.UI.Xaml;
using Windows.Storage;
using Windows.UI.WebUI;
using TpmStorageHandler.Structures;
using System.Security.Cryptography;

namespace TpmTest
{
    [TestClass]
    public class UnitTest1
    {
        private const string _dupekeyFileName = "dupeKey.secure";

        private const string TEST_MESSAGE = "ABCD";

        private static KeyWrapper GeneratePrimaryKey(Tpm2Wrapper tpm)
            => tpm.GetPrimaryStorageKey();

        private static KeyWrapper GenerateChildKey(TpmHandle primHandle, Tpm2Wrapper tpm, byte[] authSession = null)
            => tpm.CreateStorageParentKey(primHandle, authSession);

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

        private static FileEncryptionData LoadEncryptionDataFromFile(string fileName = _dupekeyFileName)
        {
            string fedJson = LoadFile(fileName);
            return JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);
        }

        private static KeyWrapper ImportKey(Tpm2Wrapper tpm, FileEncryptionData fed, KeyWrapper primKey)
        {
            KeyDuplicate keyDupe = new KeyDuplicate(
                fed.EncryptionKey,
                fed.EncryptionSeed,
                Marshaller.FromTpmRepresentation<TpmPrivate>(fed.KeyPrivate),
                Marshaller.FromTpmRepresentation<TpmPublic>(fed.KeyPublic));
            KeyWrapper childKey = tpm.ImportKey(
                primKey, keyDupe,
                new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb));
            return childKey;
        }

        private static KeyWrapper LoadStorageParent(Tpm2Wrapper tpm, KeyWrapper primKey)
        {
            string storageParentJson = LoadFile("storageParent.sec");
            Assert.IsNotNull(storageParentJson);
            Assert.IsTrue(storageParentJson.Length > 0);

            KeyWrapper storageParent = JsonConvert.DeserializeObject<KeyWrapper>(storageParentJson);
            Assert.IsNotNull(storageParent);
            Assert.IsNull(storageParent.Handle);

            storageParent = tpm.LoadObject(
                primKey.Handle, storageParent.KeyPriv, storageParent.KeyPub, null);
            Assert.IsNotNull(storageParent.Handle);

            return storageParent;
        }

        private static KeyWrapper LoadSealedObject(Tpm2Wrapper tpm, KeyWrapper storageParent,
            out PolicySession policySession)
        {
            // Load sealed object
            string sealedObjJson = LoadFile("sealedObj.sec");
            Assert.IsNotNull(sealedObjJson);
            Assert.IsTrue(sealedObjJson.Length > 0);

            KeyWrapper sealedObj = JsonConvert.DeserializeObject<KeyWrapper>(sealedObjJson);
            Assert.IsNotNull(sealedObj);
            Assert.IsNotNull(sealedObj.KeyPriv);
            Assert.IsNotNull(sealedObj.KeyPub);

            // Object handle must be null as it is not loaded yet
            Assert.IsNull(sealedObj.Handle);

            // Load object
            policySession = tpm.StartKeyedHashSession();
            sealedObj = tpm.LoadObject(
                storageParent.Handle, sealedObj.KeyPriv, sealedObj.KeyPub, null);
            Assert.IsNotNull(sealedObj.Handle);

            return sealedObj;
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
            KeyWrapper result = tpm.GetPrimaryStorageKey(true);

            Assert.IsNotNull(result.KeyPub);
        }

        [TestMethod]
        public void TestChildKeyCreation()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);
            KeyWrapper childKey = tpm.CreateStorageParentKey(primKey.Handle);

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

            CleanUp(tpm, new TpmHandle[] {primKey.Handle, childKey.Handle});
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

            CleanUp(tpm, new TpmHandle[] {childKey.Handle});
        }

        [TestMethod]
        public void TestDuplicateSave()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);

            // Need to ensure we have a session for verifying the key creation
            PolicySession dupeSession = tpm.StartDuplicatePolicySession();
            KeyWrapper storageParentKey = tpm.CreateStorageParentKey(primKey.Handle, dupeSession.PolicyHash);

            //// New parent
            //KeyWrapper newParent = tpm.LoadExternal(primKey.KeyPub);

            // Private child key. Use the same session the key was created under.
            KeyDuplicate storageParentDuplicate = tpm.DuplicateChildKey(
                storageParentKey, primKey, dupeSession,
                new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb));

            // No longer need the duplicate session
            tpm.FlushContext(dupeSession.AuthSession);

            //// Start an encrypt/decrypt session
            //PolicySession encDecSession = tpm.StartEncryptDecryptPolicySession();

            //// Also encrypt a test message
            //byte[] encMessage = tpm.Encrypt(
            //    Encoding.UTF8.GetBytes(TEST_MESSAGE),
            //    childKey, 
            //    null,
            //    out byte[] encryptionIv);

            //// Flush the encrypt session
            //tpm.FlushContext(encDecSession.AuthSession);

            // Store this in an object
            byte[] childPublic = storageParentDuplicate.Public.GetTpmRepresentation();
            byte[] childPrivate = storageParentDuplicate.Private.GetTpmRepresentation();

            // Create a data structure containing all necessary data
            FileEncryptionData fed = new FileEncryptionData(
                null, childPrivate, childPublic, dupeSession.PolicyHash,
                storageParentDuplicate.EncKey, storageParentDuplicate.Seed, null);
            string fedJson = JsonConvert.SerializeObject(fed);

            // Save data on disk
            SaveFile(_dupekeyFileName, fedJson, out StorageFile _);

            CleanUp(tpm, new TpmHandle[] {storageParentKey.Handle});
        }

        [TestMethod]
        public void TestImportDuplicate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = GeneratePrimaryKey(tpm);

            FileEncryptionData fed = LoadEncryptionDataFromFile();

            // File should not be empty
            Assert.IsNotNull(fed);

            var childKey = ImportKey(tpm, fed, primKey);

            // Test to see if the key was loaded
            Assert.IsNotNull(childKey.Handle);

            //// Try decrypting the previously encrypted test message
            //PolicySession encDecSession = tpm.StartEncryptDecryptPolicySession();
            //byte[] decMessage = tpm.Decrypt(
            //    fed.FileData,
            //    childKey,
            //    null,
            //    fed.EncryptionIv);

            //// Flush the decrypt session
            //tpm.FlushContext(encDecSession.AuthSession);

            //// And then check equality
            //Assert.IsNotNull(decMessage);
            //Assert.AreEqual(TEST_MESSAGE, Encoding.UTF8.GetString(decMessage));

            CleanUp(tpm, new TpmHandle[] {childKey.Handle});
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

            CleanUp(tpm, new TpmHandle[] {primKey.Handle, childKey.Handle});
        }

        [TestMethod]
        public void TestStorageParentSave()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey(true);

            Assert.IsNotNull(primKey.Handle);
            Assert.IsNotNull(primKey.KeyPub);

            // Need to ensure we have a session for verifying the key creation
            KeyWrapper storageParent = tpm.CreateStorageParentKey(primKey.Handle);

            // Save
            SaveFile("storageParent.sec", JsonConvert.SerializeObject(storageParent), out StorageFile _);

            CleanUp(tpm, new TpmHandle[] {storageParent.Handle});
        }

        [TestMethod]
        public void TestStorageParentLoad()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey(false);

            // Need to ensure we have a session for verifying the key creation
            string storageParentJson = LoadFile("storageParent.sec");

            // Deserialize
            KeyWrapper storageParent = JsonConvert.DeserializeObject<KeyWrapper>(storageParentJson);

            // Required to be null as it is not loaded
            Assert.IsNull(storageParent.Handle);

            // Load
            storageParent = tpm.LoadObject(
                primKey.Handle, storageParent.KeyPriv, storageParent.KeyPub, null);

            // Required to NOT be null as now it is loaded
            Assert.IsNotNull(storageParent.Handle);

            CleanUp(tpm, new TpmHandle[] {storageParent.Handle});

        }

        [TestMethod]
        public void TestSealedObjectCreate()
        {
            // Set up
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();

            // Load storage parent
            KeyWrapper storageParent = LoadStorageParent(tpm, primKey);

            // Create sealed object
            PolicySession policy = tpm.StartKeyedHashSession();
            KeyWrapper sealedObj = tpm.CreateSensitiveDataObject(storageParent, policy);

            // Test if loaded
            Assert.IsNotNull(sealedObj.Handle);

            // Save to disk
            SaveFile("sealedObj.sec", JsonConvert.SerializeObject(sealedObj), out StorageFile _);

            CleanUp(tpm, new TpmHandle[] {storageParent.Handle, sealedObj.Handle, policy.AuthSession});
        }

        [TestMethod]
        public void TestSealedObjectLoad()
        {
            // Set up
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();

            // Load storage parent
            KeyWrapper storageParent = LoadStorageParent(tpm, primKey);

            // Load sealed data object
            KeyWrapper sealedObj = LoadSealedObject(tpm, storageParent, out PolicySession policySession);

            CleanUp(tpm, new TpmHandle[] {storageParent.Handle, sealedObj.Handle});
        }

        [TestMethod]
        public void TestSealedObjectEncryptDecrypt()
        {
            // Set up
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();

            // Load storage parent
            KeyWrapper storageParent = LoadStorageParent(tpm, primKey);

            // Load sealed object
            KeyWrapper sealedObj = LoadSealedObject(tpm, storageParent, out PolicySession policySession);

            // Unseal
            byte[] unsealedKey = tpm.UnsealObject(sealedObj, policySession);
            Assert.IsNotNull(unsealedKey);
            Assert.IsTrue(unsealedKey.Length > 0);

            // Encrypt using .NET
            AesCng aes = new AesCng
            {
                KeySize = 128,
                BlockSize = 128,
                Key = unsealedKey,
                Mode = CipherMode.CBC
            };
            aes.GenerateIV();

            byte[] bytesToEncrypt = {1, 2, 3};
            ICryptoTransform encryptor = aes.CreateEncryptor(unsealedKey, aes.IV);
            byte[] encrypted;
            using (MemoryStream msEnc = new MemoryStream())
            {
                using (CryptoStream csEnc = new CryptoStream(msEnc, encryptor, CryptoStreamMode.Write))
                {
                    using (BinaryWriter bwEnc = new BinaryWriter(csEnc))
                    {
                        bwEnc.Write(bytesToEncrypt);
                    }

                    encrypted = msEnc.ToArray();
                }
            }

            FileEncryptionData fed = new FileEncryptionData(
                encrypted,
                sealedObj.KeyPriv,
                sealedObj.KeyPub,
                null, null, null,
                aes.IV);
            const string fileName = "encryptedFileTest.enc";
            SaveFile(fileName, JsonConvert.SerializeObject(fed), out StorageFile _);
            fed = null;
            aes.Dispose();

            fed = LoadEncryptionDataFromFile(fileName);
            AesCng aes2 = new AesCng()
            {
                KeySize = 128,
                BlockSize = 128,
                Key = unsealedKey,
                Mode = CipherMode.CBC,
                IV = fed.EncryptionIv
            };

            byte[] result;
            using (var input = new MemoryStream(fed.FileData))
            using (var output = new MemoryStream())
            {
                var decryptor = aes2.CreateDecryptor();
                using (var cryptStream = new CryptoStream(input, decryptor, CryptoStreamMode.Read))
                {
                    var buffer = new byte[16];
                    var read = cryptStream.Read(buffer, 0, buffer.Length);
                    while (read > 0)
                    {
                        output.Write(buffer, 0, read);
                        read = cryptStream.Read(buffer, 0, buffer.Length);
                    }

                    cryptStream.Flush();
                    result = output.ToArray();
                }
            }

            Assert.IsTrue(bytesToEncrypt.SequenceEqual(result));

            aes2.Dispose();

            CleanUp(tpm, new TpmHandle[] {storageParent.Handle, sealedObj.Handle});

        }
    }
}