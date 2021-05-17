using System;
using System.Collections.Generic;

namespace FYP.Data
{
    internal class FileNameMapping
    {
        public string OriginalName { get; private set; }
        public string SecureName { get; private set; }

        public FileNameMapping(string originalName, string secureName)
        {
            this.OriginalName = originalName;
            this.SecureName = secureName;
        }
    }

    internal class MasterFileList
    {
        public List<FileNameMapping> FileMappings;

        public MasterFileList()
        {
            FileMappings = new List<FileNameMapping>();
        }
    }
}