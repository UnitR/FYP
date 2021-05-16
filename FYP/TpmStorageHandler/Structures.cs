using System;
using Newtonsoft.Json;
using Tpm2Lib;

namespace TpmStorageHandler
{
    namespace Structures
    {
        [JsonObject(MemberSerialization.OptIn)]
        public class KeyWrapper
        {
            public TpmHandle Handle { get; private set; }

            public TpmPublic KeyPub { get; private set; }

            public TpmPrivate KeyPriv { get; private set; }

            [JsonProperty(propertyName: "privateArea")]
            private readonly byte[] _private;

            [JsonProperty(propertyName: "publicArea")]
            private readonly byte[] _public;

            [JsonConstructor]
            public KeyWrapper(byte[] publicArea, byte[] privateArea)
            {
                _private = privateArea;
                _public = publicArea;

                KeyPriv = Marshaller.FromTpmRepresentation<TpmPrivate>(privateArea);
                KeyPub = Marshaller.FromTpmRepresentation<TpmPublic>(publicArea);
            }

            public KeyWrapper(TpmPublic keyPublic)
            {
                if (keyPublic != null && keyPublic.unique != null)
                {
                    this.KeyPub = keyPublic;
                    this._public = keyPublic.GetTpmRepresentation();
                }
                else throw new ArgumentNullException(nameof(keyPublic), "Invalid public area of the key supplied");
            }

            public KeyWrapper(TpmHandle keyHandle, TpmPublic keyPublic)
            {
                this.Handle = keyHandle;
                this.KeyPub = keyPublic;
                if (keyPublic != null && keyPublic.unique != null)
                {
                    this._public = keyPublic?.GetTpmRepresentation();
                }
            }

            public KeyWrapper(TpmPublic keyPublic, TpmPrivate keyPrivate)
            {
                this.KeyPub = keyPublic;
                this.KeyPriv = keyPrivate;

                if (keyPublic != null && keyPublic.unique != null)
                {
                    this._public = keyPublic?.GetTpmRepresentation();
                }

                if (keyPrivate != null && keyPrivate.buffer != null)
                {
                    this._private = keyPrivate?.GetTpmRepresentation();
                }
            }

            public KeyWrapper(TpmHandle handle, TpmPublic keyPublic, TpmPrivate keyPrivate) 
                : this(keyPublic, keyPrivate)
            {
                this.Handle = handle;
            }
        }
        
        [JsonObject(MemberSerialization.OptIn)]
        public class KeyDuplicate : KeyWrapper
        {
            [JsonProperty]
            public byte[] EncKey { get; private set; }
            
            [JsonProperty]
            public byte[] Seed { get; private set; }

            [JsonConstructor]
            public KeyDuplicate(byte[] publicArea, byte[] privateArea) : base(publicArea, privateArea)
            {
            }

            public KeyDuplicate(byte[] dupePublic, byte[] dupePrivate, byte[] encryptionKey, byte[] encryptionSeed)
                : base(dupePublic, dupePrivate)
            {
                EncKey = encryptionKey;
                Seed = encryptionSeed;
            }

            public KeyDuplicate(TpmPublic dupePublic, TpmPrivate dupePrivate, byte[] encryptionKey, byte[] encyrptionSeed)
                : base(dupePublic, dupePrivate)
            {
                this.EncKey = encryptionKey;
                this.Seed = encyrptionSeed;
            }
        }

        public struct PolicySession
        {
            public AuthSession AuthSession { get; private set; }
            public PolicyTree PolicyTree { get; private set; }

            public TpmHash PolicyHash => PolicyTree.GetPolicyDigest();

            public PolicySession(AuthSession authSession, PolicyTree policyTree)
            {
                this.AuthSession = authSession;
                this.PolicyTree = policyTree;
            }
        }

    }
}