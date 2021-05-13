using System;
using System.Text;
using Windows.Services.Maps;
using Tpm2Lib;
using TpmStorageHandler.Structures;

namespace TpmStorageHandler
{
    public sealed class Tpm2Wrapper : IDisposable
    {

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

        public Tpm2Wrapper()
        {
            Tpm2Device device = new TcpTpmDevice(DEFAULT_TPM_SERVER, DEFAULT_TPM_PORT);
            device.Connect();
            Tpm2 tempTpm = new Tpm2(device);

            tempTpm._GetUnderlyingDevice().PowerCycle();
            tempTpm.Startup(Su.Clear);

            // Attach a managed TBS wrapper to the TPM for automatic resource management
            _tbs = new Tbs(tempTpm._GetUnderlyingDevice(), false);
            _tbsTpm = new Tpm2(_tbs.CreateTbsContext());

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
                    _tbsTpm.Shutdown(Su.Clear);
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
                ObjectAttr.Decrypt | ObjectAttr.Encrypt
                | ObjectAttr.UserWithAuth
                | ObjectAttr.SensitiveDataOrigin
                | ObjectAttr.AdminWithPolicy,       // allow duplication
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

        /// <summary>
        /// Creates a storage key: 2048 bit RSA paired with a 128-bit AES/CFB key.
        /// </summary>
        /// <param name="newKeyPublic">
        /// The storage key. Non-duplicatable.
        /// </param>
        /// <returns></returns>
        public TpmHandle CreatePrimaryStorageKey(out TpmPublic newKeyPublic)
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
                out newKeyPublic,
                out _, out _, out _);

            return primHandle;
        }
        
        public KeyWrapper CreateChildKey(TpmHandle primHandle, byte[] authSession = null)
        {
            TpmPublic childKeyTemplate = GetChildKeyPublic(authSession);

            TpmPrivate childKeyPrivate = _tbsTpm.Create(
                primHandle,
                new SensitiveCreate(SENS_KEY_AUTH_VAL, null),
                childKeyTemplate,
                null,
                new PcrSelection[0],
                out childKeyTemplate,
                out CreationData ckCreationData,
                out byte[] ckCreationHash,
                out TkCreation ckCreationTicket);

            return LoadChildKey(primHandle, childKeyPrivate, childKeyTemplate);
        }

        /// <summary>
        /// Duplicates a given child key belonging to the parent provided.
        /// </summary>
        /// <param name="childKey"></param>
        /// <param name="newParent"></param>
        /// <param name="policySession"></param>
        /// <returns>
        /// Duplicated key struct containing the encryption key generated, the Seed used and the private area of the key.
        /// </returns>
        public KeyDuplicate DuplicateChildKey(KeyWrapper childKey, KeyWrapper newParent, PolicySession policySession)
        {
            byte[] encKeyOut =
                _tbsTpm[policySession.AuthSession]
                    .Duplicate(childKey.Handle, newParent.Handle, null, GetmAesSymObj(), 
                        out var duplicate, out var seed);

            return new KeyDuplicate(encKeyOut, seed, duplicate, childKey.KeyPub);
        }

        public KeyWrapper ImportKey(TpmHandle parentHandle, KeyDuplicate dupe)
        {
            TpmPublic childKeyPublic = GetChildKeyPublic();
            TpmPrivate childKeyPrivate = _tbsTpm.Import(
                parentHandle,
                dupe.EncKey,
                dupe.Public,
                dupe.Private,
                dupe.Seed,
                GetmAesSymObj());
            return LoadChildKey(parentHandle, childKeyPrivate, dupe.Public);
        }

        public KeyWrapper LoadChildKeyExternal(byte[] childKeyPrivateBytes, KeyWrapper parentKey)
            => LoadChildKeyExternal(childKeyPrivateBytes, parentKey.Handle);

        public KeyWrapper LoadChildKeyExternal(byte[] childKeyPrivateBytes, TpmHandle parentHandle)
        {
            TpmPublic childKeyPublic = GetChildKeyPublic();
            TpmHandle childKeyHandle = _tbsTpm.LoadExternal(
                new Sensitive(_authVal, new byte[0], new Tpm2bSymKey(childKeyPrivateBytes)),
                childKeyPublic,
                parentHandle
            );
            
            return new KeyWrapper(
                childKeyHandle,
                childKeyPublic,
                new TpmPrivate(childKeyPrivateBytes)
            );
        }

        public KeyWrapper LoadChildKey(TpmHandle parentHandle, TpmPrivate childPrivate, TpmPublic childPublic = null)
        {
            if (childPublic == null)
            {
                childPublic = GetChildKeyPublic();
            }
            TpmHandle childkeyHandle = _tbsTpm[Auth.Default].Load(parentHandle, childPrivate, childPublic);
            return new KeyWrapper(childkeyHandle, childPublic, childPrivate);
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
            return _tbsTpm.EncryptDecrypt(
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
            return _tbsTpm.EncryptDecrypt(
                key.Handle, 1, TpmAlgId.Null, iv, encMessage, out byte[] _);
        }

        public byte[] RsaEncrypt(KeyWrapper key, byte[] message)
            => _tbsTpm.RsaEncrypt(key.Handle, message, new SchemeOaep(TpmAlgId.Sha1), null);

        public byte[] RsaDecrypt(KeyWrapper key, byte[] encMessage)
            => _tbsTpm.RsaDecrypt(key.Handle, encMessage, new SchemeOaep(TpmAlgId.Sha1), null);

        //public void Seal()
        //{
        //    _tbsTpm
        //}

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
    }
}
