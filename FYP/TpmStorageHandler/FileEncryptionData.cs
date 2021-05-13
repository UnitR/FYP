using System;
using Newtonsoft.Json;
using Tpm2Lib;

namespace TpmStorageHandler
{
    [Serializable]
    public class FileEncryptionData
    {

        /// <summary>
        /// Encrypted file data
        /// </summary>
        [JsonProperty]
        public byte[] FileData { get; private set; }

        /// <summary>
        /// The encrypted private area used for initialising the child key.
        /// This is directly connected to the encrypted file data - it is what encrypted the file originally.
        /// </summary>
        [JsonProperty]
        public byte[] KeyPrivate { get; private set; }

        [JsonProperty]
        public byte[] KeyPublic { get; private set; }

        /// <summary>
        /// Encryption IV used for encrypting the <code>EncryptionKey</code>.
        /// </summary>
        [JsonProperty]
        public byte[] EncryptionIv { get; private set; }

        /// <summary>
        /// Encryption key used for creating the duplicated key <code>KeyPrivate</code>.
        /// </summary>
        [JsonProperty]
        public byte[] EncryptionKey { get; private set; }

        /// <summary>
        /// Encryption seed used along <code>EncryptionKey</code> to generate the duplicated key <code>KeyPrivate</code>.
        /// </summary>
        [JsonProperty]
        public byte[] EncryptionSeed { get; private set; }

        [JsonIgnore]
        public TpmPublic PublicArea => Marshaller.FromTpmRepresentation<TpmPublic>(KeyPublic);

        [JsonIgnore]
        public TpmPrivate PrivateArea => Marshaller.FromTpmRepresentation<TpmPrivate>(KeyPrivate);

        public FileEncryptionData()
        {
            // empty constructor
        }

        public FileEncryptionData(
            byte[] fileData, byte[] keyPrivate, byte[] keyPublic, 
            byte[] encryptionKey, byte[] encryptionSeed
        )
        {
            FileData = fileData;
            KeyPrivate = keyPrivate;
            KeyPublic = keyPublic;
            EncryptionKey = encryptionKey;
            EncryptionSeed = encryptionSeed;
        }

        public FileEncryptionData(
            byte[] fileData, byte[] keyPrivate, byte[] keyPublic, byte[] authPolicy, 
            byte[] encryptionKey, byte[] encryptionSeed, byte[] encryptionIv
        )
        {
            this.FileData = fileData;
            this.EncryptionKey = encryptionKey;
            this.EncryptionSeed = encryptionSeed;
            this.EncryptionIv = encryptionIv;
            this.KeyPrivate = keyPrivate;
            this.KeyPublic = keyPublic;
        }
    }
}
