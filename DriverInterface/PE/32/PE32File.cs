using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using static KsDumper11.PE.NativePEStructs;

namespace KsDumper11.PE
{
    public class PE32File : PEFile
    {
        public DOSHeader DOSHeader { get; private set; }

        public byte[] DOS_Stub { get; private set; }

        public PE32Header PEHeader { get; private set; }

        public PE32File(IMAGE_DOS_HEADER dosHeader, IMAGE_NT_HEADERS32 peHeader, byte[] dosStub)
        {
            Type = PEType.PE32;
            DOSHeader = DOSHeader.FromNativeStruct(dosHeader);
            PEHeader = PE32Header.FromNativeStruct(peHeader);
            // Changed from Array to List for dynamic modification
            Sections = new List<PESection>(peHeader.FileHeader.NumberOfSections);
            // Initialize list with nulls or allow ProcessDumper to populate it via Add/Index? 
            // ProcessDumper assigns by index: peFile.Sections[i] = ...
            // So we pre-fill with nulls to keep compatibility with the indexing loop.
            for (int i = 0; i < peHeader.FileHeader.NumberOfSections; i++) Sections.Add(null);

            DOS_Stub = dosStub;
        }

        public override void SaveToDisk(string fileName)
        {
            try
            {
                using (BinaryWriter writer = new BinaryWriter(new FileStream(fileName, FileMode.Create, FileAccess.Write)))
                {
                    DOSHeader.AppendToStream(writer);
                    writer.Write(DOS_Stub);
                    PEHeader.AppendToStream(writer);
                    AppendSections(writer);
                }
            }
            catch { }
        }

        public override int GetFirstSectionHeaderOffset()
        {
            return Marshal.OffsetOf<IMAGE_NT_HEADERS32>("OptionalHeader").ToInt32() +
                PEHeader.FileHeader.SizeOfOptionalHeader;
        }

        public override void AlignSectionHeaders()
        {
            int newFileSize = DOSHeader.e_lfanew + 0x4 +
                Marshal.SizeOf<IMAGE_FILE_HEADER>() +
                PEHeader.FileHeader.SizeOfOptionalHeader +
                    (PEHeader.FileHeader.NumberOfSections * Marshal.SizeOf<IMAGE_SECTION_HEADER>());

            OrderSectionsBy(s => s.Header.PointerToRawData);

            for (int i = 0; i < Sections.Count; i++)
            {
                Sections[i].Header.VirtualAddress = AlignValue(Sections[i].Header.VirtualAddress, PEHeader.OptionalHeader.SectionAlignment);
                Sections[i].Header.VirtualSize = AlignValue(Sections[i].Header.VirtualSize, PEHeader.OptionalHeader.SectionAlignment);
                Sections[i].Header.PointerToRawData = AlignValue((uint)newFileSize, PEHeader.OptionalHeader.FileAlignment);
                Sections[i].Header.SizeOfRawData = AlignValue((uint)Sections[i].DataSize, PEHeader.OptionalHeader.FileAlignment);

                newFileSize = (int)(Sections[i].Header.PointerToRawData + Sections[i].Header.SizeOfRawData);
            }

            OrderSectionsBy(s => s.Header.VirtualAddress);
        }

        public override void FixPEHeader()
        {
            // Only zero out Bound Import. 
            // We do NOT zero out Import Table (1) or IAT (12) here blindly anymore if we reconstructed them.
            // However, the original code zeroed everything > NumberOfRvaAndSizes.
            // And specifically removed IAT.

            PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
            PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

            // Ensure RVA count covers standard entries
            if (PEHeader.OptionalHeader.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
                PEHeader.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

            PEHeader.FileHeader.SizeOfOptionalHeader = (ushort)Marshal.SizeOf<IMAGE_OPTIONAL_HEADER32>();
            FixSizeOfImage();

            int size = DOSHeader.e_lfanew + 0x4 + Marshal.SizeOf<IMAGE_FILE_HEADER>();
            PEHeader.OptionalHeader.SizeOfHeaders = AlignValue((uint)(size + PEHeader.FileHeader.SizeOfOptionalHeader + (PEHeader.FileHeader.NumberOfSections * Marshal.SizeOf<IMAGE_SECTION_HEADER>())), PEHeader.OptionalHeader.FileAlignment);

            // We do NOT call RemoveIatDirectory here anymore. IAT Reconstruction handles the directory pointers.
        }

        private uint AlignValue(uint value, uint alignment)
        {
            if (alignment == 0) return value;
            return ((value + alignment - 1) / alignment) * alignment;
        }

        private void FixSizeOfImage()
        {
            uint lastSize = 0;

            for (int i = 0; i < Sections.Count; i++)
            {
                if (Sections[i].Header.VirtualAddress + Sections[i].Header.VirtualSize > lastSize)
                {
                    lastSize = Sections[i].Header.VirtualAddress + Sections[i].Header.VirtualSize;
                }
            }
            PEHeader.OptionalHeader.SizeOfImage = AlignValue(lastSize, PEHeader.OptionalHeader.SectionAlignment);
        }

        // -------------------------------------------------------
        // New Implementation for IAT Support
        // -------------------------------------------------------

        public override uint GetNextSectionRva()
        {
            // Assumes sections are sorted by VA
            var lastSection = Sections.LastOrDefault();
            if (lastSection == null) return 0x1000; // Base RVA if no sections?

            uint endRva = lastSection.Header.VirtualAddress + lastSection.Header.VirtualSize;
            return AlignValue(endRva, PEHeader.OptionalHeader.SectionAlignment);
        }

        public override void AddSection(string name, byte[] content, uint characteristics)
        {
            PESection.PESectionHeader header = new PESection.PESectionHeader();

            // Truncate name to 8 chars
            if (name.Length > 8) name = name.Substring(0, 8);
            header.Name = name;

            uint alignment = PEHeader.OptionalHeader.SectionAlignment;
            uint fileAlignment = PEHeader.OptionalHeader.FileAlignment;

            header.VirtualAddress = GetNextSectionRva();
            header.VirtualSize = AlignValue((uint)content.Length, alignment);
            header.Characteristics = (DataSectionFlags)characteristics;

            // Raw Data pointers will be fixed in AlignSectionHeaders/SaveToDisk, 
            // but we calculate preliminary values here.
            var lastSection = Sections.LastOrDefault();
            uint rawPtr = lastSection != null ? lastSection.Header.PointerToRawData + lastSection.Header.SizeOfRawData : 0; // Re-calc in save
            header.PointerToRawData = AlignValue(rawPtr, fileAlignment);
            header.SizeOfRawData = AlignValue((uint)content.Length, fileAlignment);

            var newSection = new PESection
            {
                Header = header,
                Content = content,
                InitialSize = content.Length,
                DataSize = content.Length
            };

            Sections.Add(newSection);
            PEHeader.FileHeader.NumberOfSections = (ushort)Sections.Count;

            // Update image size immediately
            PEHeader.OptionalHeader.SizeOfImage = header.VirtualAddress + header.VirtualSize;
        }

        public override void SetDataDirectory(uint index, uint rva, uint size)
        {
            if (index < PEHeader.OptionalHeader.DataDirectory.Length)
            {
                PEHeader.OptionalHeader.DataDirectory[index].VirtualAddress = rva;
                PEHeader.OptionalHeader.DataDirectory[index].Size = size;
            }
        }
    }
}