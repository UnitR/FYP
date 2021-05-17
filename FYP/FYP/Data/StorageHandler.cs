﻿using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TpmStorageHandler;
using TpmStorageHandler.Structures;
using Windows.Storage;
using UnicodeEncoding = Windows.Storage.Streams.UnicodeEncoding;

namespace FYP.Data
{
    internal class StorageHandler : IDisposable
    {
        public enum FileAction
        {
            Encrypt,
            Decrypt
        }

        public MasterFileList FileList { get; private set; }

        internal const string FILE_NAME_STORAGE_PARENT = "storage_parent";
        internal const string FILE_NAME_MASTER_LIST = "master";
        internal const string FILE_NAME_TEMP = "TEMP";

        private readonly Tpm2Wrapper _tpm;
        private readonly KeyWrapper _primaryKey;
        private KeyWrapper _storageParentKey;

        private readonly StorageFolder _rootFolder;
        private IStorageFile _masterListFile;

        private bool _disposedValue;

        public StorageHandler(bool alsoInitialise = false)
        {
            // TODO: A deployed app would most likely not be running a simulator. Switch to a physical device.
            _tpm = new Tpm2Wrapper(Tpm2Wrapper.TpmType.Simulator);
            _primaryKey = _tpm.GetPrimaryStorageKey(true);
            _rootFolder = ApplicationData.Current.LocalFolder;

            if (alsoInitialise) this.Initialise();
        }

        public async Task Initialise()
        {
            IStorageFile storageParentFile = await _rootFolder.TryGetItemAsync(FILE_NAME_STORAGE_PARENT) as IStorageFile;
            if (storageParentFile == null)
            {
                _storageParentKey = _tpm.CreateStorageParentKey(_primaryKey.Handle);
                await SaveObjectToJsonAsync(FILE_NAME_STORAGE_PARENT, _storageParentKey);
            }
            else
            {
                _storageParentKey =
                    JsonConvert.DeserializeObject<KeyWrapper>(
                       await ReadFileAsync(FILE_NAME_STORAGE_PARENT));
                _storageParentKey = _tpm.LoadObject(
                    _primaryKey.Handle,
                    _storageParentKey.KeyPriv,
                    _storageParentKey.KeyPub,
                    null);
            }

            _masterListFile = await _rootFolder.TryGetItemAsync(FILE_NAME_MASTER_LIST) as IStorageFile;
            if (_masterListFile == null)
            {
                _masterListFile =
                    await _rootFolder.CreateFileAsync(FILE_NAME_MASTER_LIST, CreationCollisionOption.ReplaceExisting);
            }

            FileList = JsonConvert.DeserializeObject<MasterFileList>(
                await ReadFileAsync(_masterListFile));
            if (FileList == null)
            {
                FileList = new MasterFileList();
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _tpm.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                _disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~StorageHandler()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private static AesCng GetDefaultAesConfig(byte[] key, byte[] iv = null)
            => new AesCng()
            {
                KeySize = 128,
                BlockSize = 128,
                // TODO: CBC is not the best mode to use. Prefer a mode such as CFB
                Mode = CipherMode.CBC,
                Key = key,
                IV = iv ?? new byte[16]
            };

        public async Task<IStorageFile> SaveObjectToJsonAsync(string fileName, object objectToSave)
        {
            IStorageFile file = await _rootFolder.CreateFileAsync(
                fileName,
                CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteTextAsync(
                file,
                JsonConvert.SerializeObject(objectToSave, Formatting.None),
                UnicodeEncoding.Utf8 /* Always serialize and save to UTF8 for consistency */
            );

            return file;
        }

        public async Task<IStorageFile> SaveFileBytesTempAsync(FileData fileData)
        {
            IStorageFile file = await _rootFolder.CreateFileAsync(
                $"{FILE_NAME_TEMP}.{fileData.FileExtension}",
                CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteBytesAsync(file, fileData.Data);

            return file;
        }

        public async Task<string> ReadFileAsync(string fileName)
        {
            IStorageFile file = await _rootFolder.TryGetItemAsync(fileName) as IStorageFile;
            if (file == null) throw new ArgumentException("File does not exist.", nameof(fileName));

            return await FileIO.ReadTextAsync(file, UnicodeEncoding.Utf8);
        }

        public async Task<string> ReadFileAsync(IStorageFile file)
            => await FileIO.ReadTextAsync(file, UnicodeEncoding.Utf8);

        public async Task<IStorageFile> LoadFileAsync(string fileName) 
            => await _rootFolder.TryGetItemAsync(fileName) as IStorageFile;

        public FileEncryptionData EncryptFile(byte[] fileData)
        {
            // Create the file-specific key
            PolicySession policy = _tpm.StartKeyedHashSession();
            KeyWrapper fileKey = _tpm.CreateSensitiveDataObject(_storageParentKey, policy);

            // Unseal the key to make accessible to .NET security API
            byte[] unsealedKey = _tpm.UnsealObject(fileKey, policy);

            // Encrypt using .NET
            AesCng aes = GetDefaultAesConfig(unsealedKey);
            aes.GenerateIV();

            // Encryption streams
            ICryptoTransform encryptor = aes.CreateEncryptor(unsealedKey, aes.IV);
            byte[] encrypted;
            using (MemoryStream msEnc = new MemoryStream())
            {
                using (CryptoStream csEnc = new CryptoStream(msEnc, encryptor, CryptoStreamMode.Write))
                {
                    using (BinaryWriter bwEnc = new BinaryWriter(csEnc))
                    {
                        bwEnc.Write(fileData);
                    }

                    encrypted = msEnc.ToArray();
                }
            }

            // Create encrypted file object
            FileEncryptionData fed = new FileEncryptionData(encrypted, fileKey, aes.IV);

            // Dispose of unmanaged resources
            aes.Dispose();

            return fed;
        }

        public async Task<byte[]> DecryptFileAsync(FileEncryptionData encryptedFile)
        {
            PolicySession policy = _tpm.StartKeyedHashSession();
            KeyWrapper fileKey = encryptedFile.EncryptionKey;
            fileKey = _tpm.LoadObject(
                _storageParentKey.Handle,
                fileKey.KeyPriv, fileKey.KeyPub,
                null);
            byte[] unsealedKey = _tpm.UnsealObject(fileKey, policy);

            AesCng aes = GetDefaultAesConfig(
                unsealedKey, encryptedFile.EncryptionIv);

            byte[] result;
            using (var msIn = new MemoryStream(encryptedFile.FileData))
            using (var msOut = new MemoryStream())
            {
                var decryptor = aes.CreateDecryptor();
                using (var csDec = new CryptoStream(msIn, decryptor, CryptoStreamMode.Read))
                {
                    var buffer = new byte[1024];
                    var read = csDec.Read(buffer, 0, buffer.Length);
                    while (read > 0)
                    {
                        msOut.Write(buffer, 0, read);
                        read = await csDec.ReadAsync(buffer, 0, buffer.Length);
                    }

                    csDec.Flush();
                    result = msOut.ToArray();
                }
            }

            return result;
        }

        public async Task<string> UpdateMasterListFileAsync(string originalFileName)
        {
            // Generate a random string
            byte[] randomBytes = _tpm.GetRandom(16);
            string randString = Convert.ToBase64String(randomBytes);
            randString = String.Join("_", randString.Split(Path.GetInvalidFileNameChars()));

            // Test if a file with that name exists
            bool isNameValid = false;
            try
            {
                IStorageFile file = await _rootFolder.GetFileAsync(randString);
            }
            catch (Exception e)
            {
                isNameValid = true;
            }

            if (!isNameValid) await UpdateMasterListFileAsync(originalFileName); // recursive call to generate another random string
            
            var masterFile = await UpdateMasterListFileAsync(originalFileName, randString);
            return randString;
        }

        public async Task<IStorageFile> UpdateMasterListFileAsync(string originalFileName, string securedFileName)
        {
            try
            {
                AppendToMasterList(originalFileName, securedFileName);
                return await SaveObjectToJsonAsync(FILE_NAME_MASTER_LIST, FileList);
            }
            catch (Exception e)
            {
                throw new FileLoadException("Failed to update the master file.", e);
            }
        }

        private void AppendToMasterList(string originalFileName, string securedFileName)
            => FileList.FileMappings.Add(
                new FileNameMapping(
                    originalFileName, securedFileName));

        public string ObfuscateString(string stringToHide)
        {
            // TODO: This method should create a hash of a provided string
            throw new NotImplementedException();
        }
    }
}
