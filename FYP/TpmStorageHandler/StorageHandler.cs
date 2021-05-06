using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace TpmStorageHandler
{
    public class StorageHandler
    {
        private const string DEFAULT_TPM_SERVER_NAME = "127.0.0.1";
        private const int DEFAULT_TPM_PORT = 2321;

        public static Tpm2 ConnectTpm()
        {
            Tpm2Device device = new TcpTpmDevice(DEFAULT_TPM_SERVER_NAME, DEFAULT_TPM_PORT);
            device.Connect();
            Tpm2 tpm = new Tpm2(device);

            return tpm;
        }

        public static void ShutdownTpm(Tpm2 targetTpm)
        {
            targetTpm?.Dispose();
        }
    }
}
