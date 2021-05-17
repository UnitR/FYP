using System;
using Newtonsoft.Json;
using Tpm2Lib;

namespace TpmStorageHandler
{
    namespace Structures
    {
        [Serializable]
        [JsonObject(MemberSerialization.OptOut)]
        public class FileEncryptionData
        {
            /// <summary>
            /// Encrypted file data
            /// </summary>
            [JsonProperty(propertyName: "data")]
            public byte[] FileData { get; private set; }

            /// <summary>
            /// The encrypted private area used for initialising the child key.
            /// This is directly connected to the encrypted file data - it is what encrypted the file originally.
            /// </summary>
            [JsonProperty(propertyName: "key")]
            public KeyWrapper EncryptionKey { get; private set; }

            [JsonProperty(propertyName: "signKey")]
            public KeyWrapper SigningKey { get; private set; }

            /// <summary>
            /// Encryption IV used for encrypting the <code>EncryptionKey</code>.
            /// </summary>
            [JsonProperty(propertyName: "iv")]
            public byte[] EncryptionIv { get; private set; }

            public FileEncryptionData()
            {
                // empty constructor
            }

            public FileEncryptionData(
                byte[] fileData, KeyWrapper encryptionKey, byte[] encryptionIv
            )
            {
                FileData = fileData;
                EncryptionKey = encryptionKey;
                EncryptionIv = encryptionIv;
            }
        }
    }
}
