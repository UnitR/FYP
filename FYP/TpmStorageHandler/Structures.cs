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
            public byte[] EncKey { get; private set; }
            public byte[] Seed { get; private set; }
            public TpmPrivate Private { get; private set; }
            public TpmPublic Public { get; private set; }

            public KeyDuplicate(byte[] encKey, byte[] seed, TpmPrivate tpmPrivate, TpmPublic tpmPublic)
            {
                this.EncKey = encKey;
                this.Seed = seed;
                this.Private = tpmPrivate;
                this.Public = tpmPublic;
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