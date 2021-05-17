using System;
using System.Collections.Generic;

namespace FYP.Data
{
    internal static class StringExtensions
    {
        public static string GetFileName(this string fileName)
        {
            int extIdx = fileName.LastIndexOf('.');
            if (extIdx < 0)
            {
                throw new ArgumentException("String is not a valid file name.");
            }

            return fileName.Substring(extIdx);
        }
    }

    internal class FileNameMapping
    {
        public string OriginalName { get; private set; }
        public string SecureName { get; private set; }
        public string FileExt { get; private set; }

        public FileNameMapping(string originalName, string secureName)
        {
            this.OriginalName = originalName;
            this.SecureName = secureName;
            this.FileExt = originalName.GetFileName();
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