// Relative Path: KsDumper11\Utility\PEHeadersExtensions.cs
using System;
using System.Reflection.PortableExecutable;

namespace KsDumper11.Utility
{
    public static class PEHeadersExtensions
    {
        /// <summary>
        /// Calculates the file offset for a given Relative Virtual Address (RVA).
        /// Used for reading PE structures from disk.
        /// </summary>
        /// <param name="headers">The PEHeaders instance.</param>
        /// <param name="rva">The Relative Virtual Address to convert.</param>
        /// <returns>The file offset in bytes, or -1 if the RVA is invalid.</returns>
        public static int GetOffset(this PEHeaders headers, int rva)
        {
            if (headers == null)
                throw new ArgumentNullException(nameof(headers));

            // 1. Check if the RVA falls inside a Section
            int sectionIndex = headers.GetContainingSectionIndex(rva);

            if (sectionIndex >= 0)
            {
                var section = headers.SectionHeaders[sectionIndex];
                // Formula: RVA - Section.VirtualAddress + Section.PointerToRawData
                return rva - section.VirtualAddress + section.PointerToRawData;
            }

            // 2. Fallback: Check if RVA is within the PE Headers (e.g. bound imports or DOS stub)
            // Since this is for a file on disk, RVA == Offset for header data.
            if (headers.PEHeader != null && rva < headers.PEHeader.SizeOfHeaders)
            {
                return rva;
            }

            // RVA not found in sections or headers
            return -1;
        }
    }
}