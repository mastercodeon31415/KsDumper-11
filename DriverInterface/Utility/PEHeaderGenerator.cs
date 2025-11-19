// Relative Path: Utility\PEHeaderGenerator.cs
using System;
using System.IO;
using System.Runtime.InteropServices;
using KsDumper11.PE;

namespace KsDumper11.Utility
{
    public static class PEHeaderGenerator
    {
        /// <summary>
        /// Generates a valid PE Header for in-memory dumps.
        /// Updated: Uses standard 0x2000 Section Alignment and 0x200 File Alignment 
        /// to match standard .NET/Windows PE layout.
        /// </summary>
        public static byte[] GenerateHeader(ulong baseAddress, uint imageSize, ulong entryPointAddr, bool is64Bit)
        {
            // Standard Windows Alignment
            uint sectionAlignment = 0x2000;
            uint fileAlignment = 0x200;

            // The code (.text) usually starts at RVA 0x2000 and File Offset 0x200
            uint codeBaseRva = 0x2000;
            uint codeRawOffset = 0x200;

            uint alignedImageSize = AlignUp(imageSize, sectionAlignment);
            if (alignedImageSize == 0) alignedImageSize = 0xA00000;

            // Calculate RVA for EntryPoint
            uint entryPointRva = 0;
            if (entryPointAddr > baseAddress && entryPointAddr < baseAddress + alignedImageSize)
            {
                entryPointRva = (uint)(entryPointAddr - baseAddress);
            }
            // If EP is 0, default to start of code
            if (entryPointRva == 0) entryPointRva = codeBaseRva;

            // Calculate SizeOfCode
            uint sizeOfCode = (alignedImageSize > codeBaseRva) ? alignedImageSize - codeBaseRva : 0;

            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // DOS Header
                var dosHeader = new NativePEStructs.IMAGE_DOS_HEADER();
                dosHeader.e_magic = "MZ".ToCharArray();
                dosHeader.e_lfanew = 0x40;

                IntPtr ptr = MarshalUtility.AllocEmptyStruct<NativePEStructs.IMAGE_DOS_HEADER>();
                Marshal.StructureToPtr(dosHeader, ptr, false);
                byte[] dosBytes = new byte[Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>()];
                Marshal.Copy(ptr, dosBytes, 0, dosBytes.Length);
                Marshal.FreeHGlobal(ptr);
                writer.Write(dosBytes);

                // NT Headers
                writer.BaseStream.Position = dosHeader.e_lfanew;

                uint sizeOfOptional = is64Bit ? (uint)Marshal.SizeOf<NativePEStructs.IMAGE_OPTIONAL_HEADER64>()
                                              : (uint)Marshal.SizeOf<NativePEStructs.IMAGE_OPTIONAL_HEADER32>();
                uint sizeOfSectionHeader = (uint)Marshal.SizeOf<NativePEStructs.IMAGE_SECTION_HEADER>();

                // Headers must fit within the first 0x200 bytes
                uint headersEnd = (uint)dosHeader.e_lfanew +
                                  4 + (uint)Marshal.SizeOf<NativePEStructs.IMAGE_FILE_HEADER>() +
                                  sizeOfOptional +
                                  sizeOfSectionHeader;

                uint sizeOfHeadersAligned = AlignUp(headersEnd, fileAlignment);

                if (is64Bit)
                {
                    var nt64 = new NativePEStructs.IMAGE_NT_HEADERS64();
                    nt64.Signature = "PE\0\0".ToCharArray();
                    nt64.FileHeader.Machine = 0x8664;
                    nt64.FileHeader.NumberOfSections = 1;
                    nt64.FileHeader.TimeDateStamp = (uint)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                    nt64.FileHeader.SizeOfOptionalHeader = (ushort)sizeOfOptional;
                    nt64.FileHeader.Characteristics = 0x0022;

                    nt64.OptionalHeader.Magic = (ushort)NativePEStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                    nt64.OptionalHeader.ImageBase = baseAddress;
                    nt64.OptionalHeader.SectionAlignment = sectionAlignment;
                    nt64.OptionalHeader.FileAlignment = fileAlignment;
                    nt64.OptionalHeader.MajorOperatingSystemVersion = 6;
                    nt64.OptionalHeader.SizeOfImage = alignedImageSize;
                    nt64.OptionalHeader.SizeOfHeaders = sizeOfHeadersAligned;
                    nt64.OptionalHeader.Subsystem = 2;
                    nt64.OptionalHeader.DllCharacteristics = 0x8140;
                    nt64.OptionalHeader.AddressOfEntryPoint = entryPointRva;
                    nt64.OptionalHeader.BaseOfCode = codeBaseRva;
                    nt64.OptionalHeader.SizeOfCode = sizeOfCode;
                    nt64.OptionalHeader.SizeOfInitializedData = sizeOfCode;
                    nt64.OptionalHeader.NumberOfRvaAndSizes = 16;
                    nt64.OptionalHeader.DataDirectory = new NativePEStructs.IMAGE_DATA_DIRECTORY[16];

                    ptr = MarshalUtility.AllocEmptyStruct<NativePEStructs.IMAGE_NT_HEADERS64>();
                    Marshal.StructureToPtr(nt64, ptr, false);
                    byte[] ntBytes = new byte[Marshal.SizeOf<NativePEStructs.IMAGE_NT_HEADERS64>()];
                    Marshal.Copy(ptr, ntBytes, 0, ntBytes.Length);
                    Marshal.FreeHGlobal(ptr);
                    writer.Write(ntBytes);
                }
                else
                {
                    var nt32 = new NativePEStructs.IMAGE_NT_HEADERS32();
                    nt32.Signature = "PE\0\0".ToCharArray();
                    nt32.FileHeader.Machine = 0x014c;
                    nt32.FileHeader.NumberOfSections = 1;
                    nt32.FileHeader.TimeDateStamp = (uint)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                    nt32.FileHeader.SizeOfOptionalHeader = (ushort)sizeOfOptional;
                    nt32.FileHeader.Characteristics = 0x0102;

                    nt32.OptionalHeader.Magic = (ushort)NativePEStructs.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
                    nt32.OptionalHeader.ImageBase = (uint)baseAddress;
                    nt32.OptionalHeader.SectionAlignment = sectionAlignment;
                    nt32.OptionalHeader.FileAlignment = fileAlignment;
                    nt32.OptionalHeader.MajorOperatingSystemVersion = 6;
                    nt32.OptionalHeader.SizeOfImage = alignedImageSize;
                    nt32.OptionalHeader.SizeOfHeaders = sizeOfHeadersAligned;
                    nt32.OptionalHeader.Subsystem = 2;
                    nt32.OptionalHeader.DllCharacteristics = 0x8140;
                    nt32.OptionalHeader.AddressOfEntryPoint = entryPointRva;
                    nt32.OptionalHeader.BaseOfCode = codeBaseRva;
                    nt32.OptionalHeader.BaseOfData = 0;
                    nt32.OptionalHeader.SizeOfCode = sizeOfCode;
                    nt32.OptionalHeader.SizeOfInitializedData = sizeOfCode;
                    nt32.OptionalHeader.NumberOfRvaAndSizes = 16;
                    nt32.OptionalHeader.DataDirectory = new NativePEStructs.IMAGE_DATA_DIRECTORY[16];

                    ptr = MarshalUtility.AllocEmptyStruct<NativePEStructs.IMAGE_NT_HEADERS32>();
                    Marshal.StructureToPtr(nt32, ptr, false);
                    byte[] ntBytes = new byte[Marshal.SizeOf<NativePEStructs.IMAGE_NT_HEADERS32>()];
                    Marshal.Copy(ptr, ntBytes, 0, ntBytes.Length);
                    Marshal.FreeHGlobal(ptr);
                    writer.Write(ntBytes);
                }

                // Section Header (.text)
                var section = new NativePEStructs.IMAGE_SECTION_HEADER();
                section.Name = new char[8];
                section.Name[0] = '.'; section.Name[1] = 't'; section.Name[2] = 'e'; section.Name[3] = 'x'; section.Name[4] = 't';

                section.VirtualAddress = codeBaseRva; // 0x2000
                section.VirtualSize = sizeOfCode;
                section.PointerToRawData = codeRawOffset; // 0x200
                section.SizeOfRawData = AlignUp(sizeOfCode, fileAlignment);

                section.Characteristics = NativePEStructs.DataSectionFlags.ContentCode |
                                          NativePEStructs.DataSectionFlags.MemoryExecute |
                                          NativePEStructs.DataSectionFlags.MemoryRead |
                                          NativePEStructs.DataSectionFlags.MemoryWrite;

                ptr = MarshalUtility.AllocEmptyStruct<NativePEStructs.IMAGE_SECTION_HEADER>();
                Marshal.StructureToPtr(section, ptr, false);
                byte[] secBytes = new byte[Marshal.SizeOf<NativePEStructs.IMAGE_SECTION_HEADER>()];
                Marshal.Copy(ptr, secBytes, 0, secBytes.Length);
                Marshal.FreeHGlobal(ptr);
                writer.Write(secBytes);

                // Pad header to file alignment (0x200)
                long currentPos = ms.Position;
                if (currentPos < sizeOfHeadersAligned)
                {
                    writer.Write(new byte[sizeOfHeadersAligned - currentPos]);
                }

                return ms.ToArray();
            }
        }

        private static uint AlignUp(uint val, uint alignment)
        {
            if (alignment == 0) return val;
            return (val + alignment - 1) & ~(alignment - 1);
        }
    }
}