using System;

namespace TpmStorageHandler
{
    [Serializable]
    public class FileEncryptionData
    {
        /// <summary>
        /// Encrypted file data
        /// </summary>
        public byte[] FileData { get; private set; }

        /// <summary>
        /// The encrypted private area used for initialising the child key.
        /// This is directly connected to the encrypted file data - it is what encrypted the file originally.
        /// </summary>
        public byte[] TpmPrivateArea { get; private set; }

        /// <summary>
        /// Encryption IV used for encrypting the <code>EncryptionKey</code>.
        /// </summary>
        public byte[] EncryptionIv { get; private set; }

        /// <summary>
        /// Encryption key used for creating the duplicated key <code>TpmPrivateArea</code>.
        /// </summary>
        public byte[] EncryptionKey { get; private set; }

        /// <summary>
        /// Encryption seed used along <code>EncryptionKey</code> to generate the duplicated key <code>TpmPrivateArea</code>.
        /// </summary>
        public byte[] EncryptionSeed { get; private set; }

        public FileEncryptionData(byte[] fileData, byte[] tpmPrivateArea, byte[] encryptionIv, byte[] encryptionKey, byte[] encryptionSeed)
        {
            FileData = fileData;
            TpmPrivateArea = tpmPrivateArea;
            EncryptionIv = encryptionIv;
            EncryptionKey = encryptionKey;
            EncryptionSeed = encryptionSeed;
        }
    }
}
