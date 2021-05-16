
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

        private static KeyWrapper GenerateChildKey(TpmHandle primHandle, Tpm2Wrapper tpm, byte[] authSession = null)
            => tpm.CreateStorageParentKey(primHandle, authSession);

        private static void SaveFile(string fileName, string fileData, out StorageFile file)
        {
            StorageFolder storageFolder = ApplicationData.Current.LocalFolder;
            file = storageFolder.CreateFileAsync(
                fileName,
                CreationCollisionOption.ReplaceExisting).GetAwaiter().GetResult();
            FileIO.WriteTextAsync(file, fileData).GetAwaiter().GetResult();
        }

        private static string LoadFile(string fileName)
        {
            StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
            StorageFile file = storageFolder
                .GetFileAsync(fileName).GetAwaiter().GetResult();
            return FileIO.ReadTextAsync(file).GetAwaiter().GetResult();
        }

        private static FileEncryptionData LoadEncryptionDataFromFile(string fileName)
        {
            string fedJson = LoadFile(fileName);
            return JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);
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
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();
            KeyWrapper childKey = tpm.CreateStorageParentKey(primKey.Handle);

            Assert.IsNotNull(childKey.KeyPub);

            CleanUp(tpm, new TpmHandle[] {primKey.Handle, childKey.Handle});
        }

        [TestMethod]
        public void TestEncrypt()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();
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
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();
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
            KeyWrapper primKey = tpm.GetPrimaryStorageKey(true);

            // Need to ensure we have a session for verifying the key creation
            PolicySession dupeSession = tpm.StartDuplicatePolicySession();
            KeyWrapper storageParentKey = tpm.CreateStorageParentKey(primKey.Handle, dupeSession.PolicyHash);

            //// New parent
            //KeyWrapper newParent = tpm.LoadExternal(primKey.KeyPub);

            // Private child key. Use the same session the key was created under.
            KeyDuplicate storageParentDuplicate = tpm.DuplicateChildKey(
                storageParentKey, primKey, dupeSession);

            // No longer need the duplicate session
            tpm.FlushContext(dupeSession.AuthSession);

            // Save data on disk
            SaveFile(
                _dupekeyFileName, JsonConvert.SerializeObject(storageParentDuplicate),
                out StorageFile _);

            CleanUp(tpm, new TpmHandle[] {storageParentKey.Handle});
        }

        [TestMethod]
        public void TestImportDuplicate()
        {
            Tpm2Wrapper tpm = new Tpm2Wrapper();
            KeyWrapper primKey = tpm.GetPrimaryStorageKey();

            string dupeJson = LoadFile(_dupekeyFileName);
            Assert.IsNotNull(dupeJson);
            KeyDuplicate keyDupe = JsonConvert.DeserializeObject<KeyDuplicate>(dupeJson);
            Assert.IsNotNull(keyDupe);
            Assert.IsNotNull(keyDupe.KeyPriv);
            Assert.IsNotNull(keyDupe.KeyPub);

            KeyWrapper importedDupe = tpm.ImportKey(primKey, keyDupe);
            Assert.IsNotNull(importedDupe.Handle);

            CleanUp(tpm, new TpmHandle[] {importedDupe.Handle});
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

            FileEncryptionData fed = new FileEncryptionData(encrypted, sealedObj, aes.IV);
            const string fileName = "encryptedFileTest.enc";
            SaveFile(fileName, JsonConvert.SerializeObject(fed), out StorageFile _);

            unsealedKey = null;
            fed = null;
            aes.Dispose();
            
            tpm.FlushContext(storageParent.Handle);
            tpm.FlushContext(sealedObj.Handle);
            tpm.FlushContext(policySession.AuthSession);

            // Load file data
            fed = LoadEncryptionDataFromFile(fileName);

            // Load storage parent
            storageParent = LoadStorageParent(tpm, primKey);

            // Load sealed object
            sealedObj = LoadSealedObject(tpm, storageParent, out policySession);

            // Unseal
            unsealedKey = tpm.UnsealObject(sealedObj, policySession);

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

            CleanUp(tpm, new TpmHandle[] {storageParent.Handle, sealedObj.Handle, policySession.AuthSession});
        }
    }
}