using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using static KsDumper11.PE.NativePEStructs;

namespace KsDumper11.PE
{
    public class PE64File : PEFile
    {
        public DOSHeader DOSHeader { get; private set; }

        public byte[] DOS_Stub { get; private set; }

        public PE64Header PEHeader { get; private set; }

        public PE64File(IMAGE_DOS_HEADER dosHeader, IMAGE_NT_HEADERS64 peHeader, byte[] dosStub)
        {
            Type = PEType.PE64;
            DOSHeader = DOSHeader.FromNativeStruct(dosHeader);
            PEHeader = PE64Header.FromNativeStruct(peHeader);

            // Changed to List
            Sections = new List<PESection>(peHeader.FileHeader.NumberOfSections);
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
            return Marshal.OffsetOf<IMAGE_NT_HEADERS64>("OptionalHeader").ToInt32() +
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
            PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
            PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

            if (PEHeader.OptionalHeader.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
                PEHeader.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

            PEHeader.FileHeader.SizeOfOptionalHeader = (ushort)Marshal.SizeOf<IMAGE_OPTIONAL_HEADER64>();
            FixSizeOfImage();

            int size = DOSHeader.e_lfanew + 0x4 + Marshal.SizeOf<IMAGE_FILE_HEADER>();
            PEHeader.OptionalHeader.SizeOfHeaders = AlignValue((uint)(size + PEHeader.FileHeader.SizeOfOptionalHeader + (PEHeader.FileHeader.NumberOfSections * Marshal.SizeOf<IMAGE_SECTION_HEADER>())), PEHeader.OptionalHeader.FileAlignment);

            // No RemoveIatDirectory call
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
            var lastSection = Sections.LastOrDefault();
            if (lastSection == null) return 0x1000;

            uint endRva = lastSection.Header.VirtualAddress + lastSection.Header.VirtualSize;
            return AlignValue(endRva, PEHeader.OptionalHeader.SectionAlignment);
        }

        public override void AddSection(string name, byte[] content, uint characteristics)
        {
            PESection.PESectionHeader header = new PESection.PESectionHeader();
            if (name.Length > 8) name = name.Substring(0, 8);
            header.Name = name;

            uint alignment = PEHeader.OptionalHeader.SectionAlignment;
            uint fileAlignment = PEHeader.OptionalHeader.FileAlignment;

            header.VirtualAddress = GetNextSectionRva();
            header.VirtualSize = AlignValue((uint)content.Length, alignment);
            header.Characteristics = (DataSectionFlags)characteristics;

            var lastSection = Sections.LastOrDefault();
            uint rawPtr = lastSection != null ? lastSection.Header.PointerToRawData + lastSection.Header.SizeOfRawData : 0;
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