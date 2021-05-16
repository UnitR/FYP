using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TpmStorageHandler.Structures;

namespace FYP.Data
{
    class ProtectedFile
    {
        public string FileName { get; private set; }
        public FileEncryptionData FileData { get; private set; }
    }
}
