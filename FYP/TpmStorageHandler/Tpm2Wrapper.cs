using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace TpmStorageHandler
{
    public sealed class Tpm2Wrapper : IDisposable
    {

        #region --------------- Constants --------------- 
        private const string DEFAULT_TPM_SERVER = "127.0.0.1";
        private const int DEFAULT_TPM_PORT = 2321;
        #endregion

        #region --------------- Fields --------------- 

        /// <summary>
        /// TBS wrapper to wrap around the TPM for improved resource management.
        /// TBS handles any session swapping and limited resources and saves writing boilerplate code.
        /// Note that this is different from a TBS device.
        /// </summary>
        private readonly Tpm2 _tbsTpm;

        private readonly Tbs _tbs;

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
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // Never leave lingering connections to the TPM
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
        /// Creates a storage key: 2048 bit RSA paired with a 256-bit AES/CFB key.
        /// </summary>
        /// <param name="newKeyPublic">
        /// The storage key. Non-duplicatable.
        /// </param>
        /// <returns></returns>
        public TpmHandle CreateRsaPrimaryStorageKey(out TpmPublic newKeyPublic)
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

            CreationData creationData;
            TkCreation creationTicket;
            byte[] creationHash;
            byte[] keyAuth = _tbsTpm.GetRandom(24);

            TpmHandle primHandle = _tbsTpm[_authVal].CreatePrimary(
                TpmHandle.RhOwner,
                new SensitiveCreate(keyAuth, new byte[0]),
                keyTemplate,
                new byte[0],
                new PcrSelection[0],
                out newKeyPublic,
                out creationData, out creationHash, out creationTicket);

            return primHandle;
        }
    }
}
