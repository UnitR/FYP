using System;
using Tpm2Lib;

namespace TpmStorageHandler
{
    namespace Structures
    {
        public struct KeyWrapper
        {
            public TpmHandle Handle { get; private set; }
            public TpmPublic KeyPub { get; private set; }
            public TpmPrivate KeyPriv { get; private set; }

            public KeyWrapper(TpmHandle handle, TpmPublic keyPublic, TpmPrivate keyPrivate = null)
            {
                this.Handle = handle;
                this.KeyPub = keyPublic;
                this.KeyPriv = keyPrivate;
            }
        }

        public struct KeyDuplicate
        {
            public byte[] EncKeyOut { get; private set; }
            public TpmPrivate Duplicate { get; private set; }
            public byte[] Seed { get; private set; }

            public KeyDuplicate(byte[] encKeyOut, TpmPrivate duplciate, byte[] seed)
            {
                this.EncKeyOut = encKeyOut;
                this.Duplicate = duplciate;
                this.Seed = seed;
            }
        }

        public struct PolicySession
        {
            public AuthSession Session { get; private set; }
            public PolicyTree PolicyTree { get; private set; }

            public TpmHash PolicyHash => PolicyTree.GetPolicyDigest();

            public PolicySession(AuthSession session, PolicyTree policyTree)
            {
                this.Session = session;
                this.PolicyTree = policyTree;
            }
        }

    }
}