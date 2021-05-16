using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FYP.Data
{
    internal class FileData
    {
        public string Name { get; private set; }
        
        public string Type { get; private set; }

        public string FileExtension { get; private set; }
        
        public byte[] Data { get; private set; }

        public FileData(string name, string fileExtension, byte[] data)
        {
            this.Name = name;
            this.FileExtension = fileExtension;
            this.Data = data;
        }
    }
}
