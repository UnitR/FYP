using System;
using System.Linq;
using Tpm2Lib;
using TpmStorageHandler.Structures;

namespace TpmStorageHandler
{
    public sealed class Tpm2Wrapper : IDisposable
    {

        public enum TpmType
        {
            Simulator,
            Physical
        }

        #region --------------- Constants --------------- 
        private const string DEFAULT_TPM_SERVER = "127.0.0.1";
        private const int DEFAULT_TPM_PORT = 2321;
        private const int CFB_IV_SIZE = 16;

        private byte[] SENS_PRIM_KEY_AUTH_VAL = { 0xa, 0xb, 0xc };
        private byte[] SENS_KEY_AUTH_VAL = { 0x1, 0x2, 0x3 };
        #endregion

        #region --------------- Fields --------------- 

        /// <summary>
        /// TBS wrapper to wrap around the TPM for improved resource management.
        /// TBS handles any session swapping and limited resources and saves writing boilerplate code.
        /// Note that this is different from a TBS device.
        /// </summary>
        private readonly Tpm2 _tbsTpm;

        private readonly Tbs _tbs;

        private readonly TpmCc _supportedEncDecCc;

        /// <summary>
        /// Auth value used for knowledge proofs.
        /// </summary>
        private readonly AuthValue _authVal;

        /// <summary>
        /// Flag for whether this instance has been disposed or not.
        /// </summary>
        private bool disposedValue;

        #endregion

        public Tpm2Wrapper() : this(TpmType.Simulator) {}

        public Tpm2Wrapper(TpmType tpmType)
        {
            Tpm2Device device = null;
            switch (tpmType)
            {
                case TpmType.Simulator:
                    device = new TcpTpmDevice(DEFAULT_TPM_SERVER, DEFAULT_TPM_PORT);
                    break;
                case TpmType.Physical:
                    // TODO: Connect to a physical device
                    break;
                default:
                    throw new ArgumentException("Invalid TPM type connection.");
            }
            device?.Connect();
            Tpm2 tempTpm = new Tpm2(device);

            tempTpm._GetUnderlyingDevice().PowerCycle();
            tempTpm.Startup(Su.Clear);

            // Attach a managed TBS wrapper to the TPM for automatic resource management
            _tbs = new Tbs(tempTpm._GetUnderlyingDevice(), false);
            _tbsTpm = new Tpm2(_tbs.CreateTbsContext());

            // If running on a simulator, reset the dictionary attack lockout
            // as it is only intervenes in testing currently.
            // TODO: Remove simulator reset for pre-production testing or testing specific functionality.
            if (tpmType == TpmType.Simulator)
            {
                _tbsTpm.DictionaryAttackLockReset(TpmHandle.RhLockout);
            }

            // Auth-value to control later access to hash objects
            _authVal = new AuthValue();

            _supportedEncDecCc =
                _tbsTpm.Helpers.IsImplemented(TpmCc.EncryptDecrypt2) ?
                    TpmCc.EncryptDecrypt2 : TpmCc.EncryptDecrypt;
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // Never leave lingering connections to the TPM
                    //_tbsTpm.Shutdown(Su.Clear);
                    _tbs?.Dispose();
                    _tbsTpm?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to nulls
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~Tpm2Wrapper()
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

        /// <summary>
        /// Flush the given context. Wrapper around the inner tpm object function.
        /// </summary>
        /// <param name="handle"></param>
        public void FlushContext(TpmHandle handle)
            => _tbsTpm.FlushContext(handle);

        private static SymDefObject GetmAesSymObj()
            => new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb);

        private static TpmPublic GetChildKeyPublic(byte[] authSession = null)
            => new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.UserWithAuth
                | ObjectAttr.SensitiveDataOrigin,       // allow duplication
                authSession,                        // expected policy hash
                new SymcipherParms(
                    GetmAesSymObj()
                ),
                new Tpm2bDigestSymcipher());

        public AuthSession StartHmacAuthSession(AuthValue userAuth = null)
        {
            if (userAuth == null)
            {
                userAuth = _authVal;
            }
            TpmHandle hashHandle = _tbsTpm.HashSequenceStart(userAuth, TpmAlgId.Sha256);
            return _tbsTpm.StartAuthSessionEx(TpmSe.Hmac, TpmAlgId.Sha256);
        }

        private TpmHandle GeneratePrimaryKey(TpmHandle persistentHandle, out TpmPublic primKeyPub)
        {
            // Key parameters
            TpmPublic keyTemplate = new TpmPublic(
                TpmAlgId.Sha256,
ObjectAttr.Decrypt                                                          // Storage keys are decryption keys,
                | ObjectAttr.Restricted                                                     // Must be restricted - per definition
                | ObjectAttr.FixedParent | ObjectAttr.FixedTPM                              // fixed parent, cannot be duplicated
                | ObjectAttr.UserWithAuth                                                   // authenticate users with HMAC or PWAP
                | ObjectAttr.SensitiveDataOrigin,                                           // origin of sensitive data; not provided externally
                new byte[0],
                new RsaParms(
                    new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                    new NullAsymScheme(),
                    2048,
                    0),
                new Tpm2bPublicKeyRsa());

            TpmHandle primHandle = _tbsTpm[_authVal].CreatePrimary(
                TpmHandle.RhOwner,
                new SensitiveCreate(SENS_PRIM_KEY_AUTH_VAL, new byte[0]),
                keyTemplate,
                new byte[0],
                new PcrSelection[0],
                out primKeyPub,
                out _, out _, out _);

            // Clear everything in the same slot as this
            _tbsTpm._AllowErrors().EvictControl(TpmRh.Owner, persistentHandle, persistentHandle);

            // Make the key NV-resident
            _tbsTpm.EvictControl(TpmRh.Owner, primHandle, persistentHandle);

            // Flush the primary handle
            _tbsTpm.FlushContext(primHandle);

            return persistentHandle;
        }

        /// <summary>
        /// Creates a storage key: 2048 bit RSA paired with a 128-bit AES/CFB key.
        /// </summary>
        /// <returns></returns>
        public KeyWrapper GetPrimaryStorageKey(bool generateIfMissing = false)
        {
            // Set up a persistent handle
            TpmHandle persistent = TpmHandle.Persistent(0x5555);

            // Try to get the persistent handle
            TpmPublic persPublic = _tbsTpm.
                _AllowErrors().
                ReadPublic(persistent, out byte[] name, out byte[] qName);

            // If failed to retrieve the primary key, generate it
            if (!_tbsTpm._LastCommandSucceeded() && generateIfMissing)
            {
                GeneratePrimaryKey(persistent, out persPublic);
            }

            return new KeyWrapper(persistent, persPublic);
        }

        public KeyWrapper CreateStorageParentKey(TpmHandle primHandle, byte[] authSession = null)
        {
            // Restricted-Decrypt is referred to as a Storage Parent.
            // This will be the parent of all other keys for individual files.
            TpmPublic keyTemplate = new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Restricted | ObjectAttr.Decrypt 
                                      | ObjectAttr.EncryptedDuplication
                                      | ObjectAttr.UserWithAuth
                                      | ObjectAttr.SensitiveDataOrigin
                                      | ObjectAttr.AdminWithPolicy, // allow duplication
                authSession, // expected policy hash
                new SymcipherParms(
                    GetmAesSymObj()
                ),
                new Tpm2bDigestSymcipher());

            AuthValue auth = new AuthValue(SENS_PRIM_KEY_AUTH_VAL);
            TpmPrivate childKeyPrivate = _tbsTpm[auth].Create(
                primHandle,
                new SensitiveCreate(SENS_PRIM_KEY_AUTH_VAL, null),
                keyTemplate,
                null,
                new PcrSelection[0],
                out keyTemplate,
                out CreationData ckCreationData,
                out byte[] ckCreationHash,
                out TkCreation ckCreationTicket);

            return LoadObject(primHandle, childKeyPrivate, keyTemplate, auth);
        }

        /// <summary>
        /// Duplicates a given child key belonging to the parent provided.
        /// </summary>
        /// <param name="childKey"></param>
        /// <param name="newParent"></param>
        /// <param name="policySession"></param>
        /// <param name="symDef"></param>
        /// <returns>
        /// Duplicated key struct containing the encryption key generated, the Seed used and the private area of the key.
        /// </returns>
        public KeyDuplicate DuplicateChildKey(KeyWrapper childKey, KeyWrapper newParent, PolicySession policySession, SymDefObject symDef = null)
        {
            if (symDef == null)
            {
                if (childKey.KeyPub.objectAttributes.HasFlag(ObjectAttr.EncryptedDuplication))
                {
                    // If encryption is required for the child key, default to AES128 in CFB mode
                    symDef = GetmAesSymObj();
                }
                else symDef = SymDefObject.NullObject();
            }
            byte[] encKeyOut =
                _tbsTpm[policySession.AuthSession]
                    .Duplicate(childKey.Handle, newParent.Handle, null, symDef,
                        out var duplicate, out var seed);

            return new KeyDuplicate(childKey.KeyPub, duplicate, encKeyOut, seed);
        }

        public KeyWrapper ImportKey(KeyWrapper parent, KeyDuplicate dupe, SymDefObject symDef = null)
        {
            // Params for import - depending on the symmetric algorithm provided
            byte[] encKey = new byte[0];
            byte[] inSymSeed = new byte[0];

            // Avoid null values - leads to an error return code
            if (symDef == null)
            {
                if ((dupe.Seed != null && dupe.Seed.Length > 0) 
                    && (dupe.EncKey != null && dupe.EncKey.Length > 0))
                {
                    symDef = GetmAesSymObj();
                    encKey = dupe.EncKey;
                    inSymSeed = dupe.Seed;
                }
                else symDef = SymDefObject.NullObject();
            }

            AuthValue authValue = new AuthValue(SENS_PRIM_KEY_AUTH_VAL);
            PolicySession authSession = StartImportPolicySession();
            TpmPrivate dupePrivate =
                _tbsTpm[authValue]
                    .Import(
                        parent.Handle,
                        encKey,
                        dupe.KeyPub,
                        dupe.KeyPriv,
                        inSymSeed,
                        symDef);

            // Load the imported key
            return LoadObject(parent.Handle, dupePrivate, dupe.KeyPub, authValue);
        }

        //public KeyWrapper LoadChildKeyExternal(byte[] childKeyPrivateBytes, KeyWrapper parentKey)
        //    => LoadChildKeyExternal(childKeyPrivateBytes, parentKey.Handle);

        public TpmHandle LoadExternal(KeyWrapper parent, KeyWrapper external)
        {
            AuthValue auth = new AuthValue(SENS_PRIM_KEY_AUTH_VAL);
            return _tbsTpm.LoadExternal(
                new Sensitive(auth, null, new Tpm2bSymKey(external.KeyPriv)),
                external.KeyPub, parent.Handle);

        }

        public KeyWrapper LoadObject(TpmHandle parentHandle, TpmPrivate objPrivate, TpmPublic objPublic,
            AuthValue auth)
        {
            // Default to the primary auth
            auth = auth ?? new AuthValue(SENS_PRIM_KEY_AUTH_VAL);
            TpmHandle objHandle = _tbsTpm[auth].Load(parentHandle, objPrivate, objPublic);
            return new KeyWrapper(objHandle, objPublic, objPrivate);
        }

        public byte[] Encrypt(byte[] message, KeyWrapper key, out byte[] iv)
            => Encrypt(message, key, null, out iv);

        public byte[] Encrypt(byte[] message, KeyWrapper key, PolicySession? session, out byte[] iv)
        {
            iv = _tbsTpm.GetRandom(CFB_IV_SIZE);
            if (session.HasValue)
            {
                return _tbsTpm[session.Value.AuthSession].EncryptDecrypt(
                    key.Handle, 0, TpmAlgId.Null, iv, message, out byte[] _);
            }
            return _tbsTpm[Auth.Pw].EncryptDecrypt(
                key.Handle, 0, TpmAlgId.Null, iv, message, out byte[] _);
        }

        public byte[] Decrypt(byte[] encMessage, KeyWrapper key, byte[] iv)
            => Decrypt(encMessage, key, null, iv);

        public byte[] Decrypt(byte[] encMessage, KeyWrapper key, PolicySession? session, byte[] iv)
        {
            if (session.HasValue)
            {
                return _tbsTpm[session.Value.AuthSession].EncryptDecrypt(
                    key.Handle, 1, TpmAlgId.Null, iv, encMessage, out byte[] _);
            }

            AuthValue auth = new AuthValue(SENS_PRIM_KEY_AUTH_VAL);
            return _tbsTpm[auth].EncryptDecrypt(
                key.Handle, 1, TpmAlgId.Null, iv, encMessage, out byte[] _);
        }

        public byte[] RsaEncrypt(KeyWrapper key, byte[] message)
            => _tbsTpm.RsaEncrypt(key.Handle, message, new SchemeOaep(TpmAlgId.Sha1), null);

        public byte[] RsaDecrypt(KeyWrapper key, byte[] encMessage)
            => _tbsTpm.RsaDecrypt(key.Handle, encMessage, new SchemeOaep(TpmAlgId.Sha1), null);

        public KeyWrapper CreateSensitiveDataObject(KeyWrapper parent, PolicySession policy, TpmPublic template = null, byte[] objectData = null)
        {
            if (template != null)
            {
                if (template.objectAttributes.HasFlag(ObjectAttr.Encrypt)
                    || template.objectAttributes.HasFlag(ObjectAttr.Sign))
                {
                    throw new ArgumentException(
                        "The file key must be created as a Sensitive Data Object. This means NOT setting Object Attributes Encrypt and Sign ");
                }
                else if (template.objectAttributes.HasFlag(ObjectAttr.Decrypt))
                {
                    throw new ArgumentException(
                        "The sensitive data object cannot have a Decrypt attribute set. That will prevent unsealing for encryption.");
                }
            }

            // Authentication
            AuthValue authValue = new AuthValue(SENS_PRIM_KEY_AUTH_VAL);

            // Determine object attributes based on parent
            ObjectAttr attr = ObjectAttr.UserWithAuth;
            if (parent.KeyPub.objectAttributes.HasFlag(ObjectAttr.EncryptedDuplication))
            {
                // Encrypted duplication is required to be set if the parent has the same attribute
                attr |= ObjectAttr.EncryptedDuplication;
            }

            // Create the sealed object from random bits
            if (objectData == null)
            {
                const ushort keyLength = 16;
                objectData = _tbsTpm.GetRandom(keyLength);
                // Some TPM implementations might return less than the requested number of bytes
                int numPasses = Convert.ToInt32(Math.Ceiling((double) keyLength / objectData.Length));
                int digestSize = objectData.Length;
                if (numPasses > 1)
                {
                    for (int i = 1; i < numPasses; i++)
                    {
                        objectData = objectData.Concat(GetRandom((ushort)digestSize)).ToArray();
                    }
                    if (objectData.Length > keyLength)
                    {
                        objectData = objectData.Take(keyLength).ToArray();
                    }
                }
            }
            TpmPublic objPub
                = template
                  ??
                  new TpmPublic(
                      TpmAlgId.Sha256,
                      attr,
                      policy.PolicyHash,
                      new KeyedhashParms(),
                      new Tpm2bDigestKeyedhash());
            TpmPrivate objPriv = _tbsTpm[authValue].Create(
                parent.Handle,
                new SensitiveCreate(
                    SENS_KEY_AUTH_VAL, 
                    objectData
                ),
                objPub,
                new byte[0],
                new PcrSelection[0],
                out objPub,
                out CreationData ckCreationData,
                out byte[] ckCreationHash,
                out TkCreation ckCreationTicket);

            return LoadObject(parent.Handle, objPriv, objPub, authValue);
        }

        public byte[] UnsealObject(KeyWrapper sealedObj, PolicySession session) => _tbsTpm[session.AuthSession].Unseal(sealedObj.Handle);

        public PolicySession StartDuplicatePolicySession()
        {
            AuthSession session = _tbsTpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            PolicyTree policy = new PolicyTree(TpmAlgId.Sha256);
            policy.Create(new PolicyAce[]
            {
                new TpmPolicyCommand(TpmCc.Duplicate),
                "duplicate"
            });
            session.RunPolicy(_tbsTpm, policy, "duplicate");

            return new PolicySession(session, policy);
        }

        public PolicySession StartEncryptDecryptPolicySession()
        {
            AuthSession session = _tbsTpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            PolicyTree policy = new PolicyTree(TpmAlgId.Sha256);
            const string encDecPolBranch = "encDec";
            policy.Create(new PolicyAce[]
            {
                new TpmPolicyCommand(_supportedEncDecCc),
                encDecPolBranch
            });
            session.RunPolicy(_tbsTpm, policy, encDecPolBranch);

            return new PolicySession(session, policy);
        }

        public PolicySession StartImportPolicySession()
        {
            AuthSession session = _tbsTpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            PolicyTree policy = new PolicyTree(TpmAlgId.Sha256);
            policy.Create(new PolicyAce[]
            {
                new TpmPolicyCommand(TpmCc.Import),
                "import"
            });
            session.RunPolicy(_tbsTpm, policy, "import");

            return new PolicySession(session, policy);
        }

        public PolicySession StartKeyedHashSession()
        {
            const string sessionBranchName = "create";
            AuthSession session = _tbsTpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);

            PcrSelection[] pcrsToQuote = new PcrSelection[]
            {
                new PcrSelection(TpmAlgId.Sha256, new uint[] { 1, 2, 3 })
            };
            _tbsTpm.PcrRead(
                pcrsToQuote,
                out pcrsToQuote,
                out Tpm2bDigest[] pcrValues);
            var expectedPcrsVals = new PcrValueCollection(pcrsToQuote, pcrValues);

            PolicyTree policy = new PolicyTree(TpmAlgId.Sha256);
            policy.Create(new PolicyAce[]
            {
                new TpmPolicyLocality(LocalityAttr.TpmLocZero),
                new TpmPolicyPcr(expectedPcrsVals),
                sessionBranchName
            });
            session.RunPolicy(_tbsTpm, policy, sessionBranchName);

            return new PolicySession(session, policy);
        }

        public byte[] GetRandom(ushort bytesRequested)
            => _tbsTpm.GetRandom(bytesRequested);
    }
}
