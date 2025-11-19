// Relative Path: ProcessDumper.cs
using KsDumper11.Driver;
using KsDumper11.PE;
using KsDumper11.Utility;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace KsDumper11
{
    public class ProcessDumper
    {
        public ProcessDumper(KsDumperDriverInterface kernelDriver)
        {
            this.kernelDriver = kernelDriver;
        }

        private static bool IsWin64Emulator(Process process)
        {
            bool flag = Environment.OSVersion.Version.Major > 5 || (Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1);
            bool retVal;
            return flag && (ProcessDumper.NativeMethods.IsWow64Process(process.Handle, out retVal) && retVal);
        }

        public bool DumpProcess(Process processSummary, out PEFile outputFile)
        {
            ulong baseAddr = (ulong)processSummary.MainModule.BaseAddress.ToInt64();
            uint size = 0;
            try { size = (uint)processSummary.MainModule.ModuleMemorySize; } catch { }
            return DumpProcessImpl(processSummary.Id, processSummary.ProcessName, baseAddr, size, 0, !IsWin64Emulator(processSummary), false, out outputFile);
        }

        public bool DumpProcess(ProcessSummary processSummary, out PEFile outputFile)
        {
            return DumpProcessImpl(processSummary.ProcessId, processSummary.ProcessName, processSummary.MainModuleBase, processSummary.MainModuleImageSize, processSummary.MainModuleEntryPoint, !processSummary.IsWOW64, false, out outputFile);
        }

        private bool DumpProcessImpl(int processId, string processName, ulong basePointer, uint imageSize, ulong entryPoint, bool is64Bit, bool forceReconstruction, out PEFile outputFile)
        {
            outputFile = null;
            Logger.SkipLine();
            Logger.Log("Targeting Process: {0} ({1})", new object[] { processName, processId });

            bool headerCorrupt = true;
            NativePEStructs.IMAGE_DOS_HEADER dosHeader = new NativePEStructs.IMAGE_DOS_HEADER();

            if (!forceReconstruction)
            {
                dosHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_DOS_HEADER>(processId, basePointer);
                headerCorrupt = (dosHeader.e_magic[0] != 'M' || dosHeader.e_magic[1] != 'Z');
            }

            bool isReconstructed = false;

            if (headerCorrupt)
            {
                Logger.Log(forceReconstruction ? "Forcing Reconstruction (Flat Map)..." : "Invalid PE Header. Reconstructing...", Array.Empty<object>());
                if (imageSize == 0) { imageSize = 0xA00000; Logger.Log("Using default Image Size: 10MB", Array.Empty<object>()); }

                byte[] syntheticHeader = PEHeaderGenerator.GenerateHeader(basePointer, imageSize, entryPoint, is64Bit);

                using (System.IO.MemoryStream ms = new System.IO.MemoryStream(syntheticHeader))
                using (System.IO.BinaryReader br = new System.IO.BinaryReader(ms))
                {
                    IntPtr ptr = MarshalUtility.AllocZeroFilled(syntheticHeader.Length);
                    Marshal.Copy(syntheticHeader, 0, ptr, syntheticHeader.Length);

                    dosHeader = MarshalUtility.GetStructFromMemory<NativePEStructs.IMAGE_DOS_HEADER>(ptr, false);
                    IntPtr ntPtr = ptr + dosHeader.e_lfanew;

                    if (is64Bit)
                    {
                        var nt64 = MarshalUtility.GetStructFromMemory<NativePEStructs.IMAGE_NT_HEADERS64>(ntPtr, false);
                        outputFile = new PE64File(dosHeader, nt64, new byte[0]);
                    }
                    else
                    {
                        var nt32 = MarshalUtility.GetStructFromMemory<NativePEStructs.IMAGE_NT_HEADERS32>(ntPtr, false);
                        outputFile = new PE32File(dosHeader, nt32, new byte[0]);
                    }

                    Marshal.FreeHGlobal(ptr);
                    isReconstructed = true;

                    var syntheticSection = new PESection();
                    syntheticSection.Header = new PESection.PESectionHeader();
                    syntheticSection.Header.Name = ".text";

                    // UPDATE: Use Standard Alignment (RVA 0x2000, Raw 0x200)
                    syntheticSection.Header.VirtualAddress = 0x2000;
                    syntheticSection.Header.PointerToRawData = 0x200;

                    uint alignedImageSize = (imageSize + 0x1FF) & ~0x1FFu;
                    // Data size is roughly ImageSize - HeaderSize(0x200)
                    uint secSize = (alignedImageSize > 0x200) ? alignedImageSize - 0x200 : 0x200;

                    syntheticSection.Header.VirtualSize = secSize;
                    syntheticSection.Header.SizeOfRawData = secSize;
                    syntheticSection.Header.Characteristics = NativePEStructs.DataSectionFlags.ContentCode |
                                                              NativePEStructs.DataSectionFlags.MemoryExecute |
                                                              NativePEStructs.DataSectionFlags.MemoryRead |
                                                              NativePEStructs.DataSectionFlags.MemoryWrite;

                    syntheticSection.InitialSize = (int)secSize;

                    if (outputFile.Sections.Count > 0) outputFile.Sections[0] = syntheticSection;
                    else outputFile.Sections.Add(syntheticSection);
                }
            }
            else
            {
                Logger.Log("Valid PE Header found. Dumping Existing Header.", Array.Empty<object>());
                ulong peHeaderPointer = basePointer + (ulong)dosHeader.e_lfanew;
                ulong dosStubPointer = basePointer + (ulong)Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>();
                int stubSize = dosHeader.e_lfanew - Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>();
                byte[] dosStub = (stubSize > 0) ? this.ReadProcessBytes(processId, dosStubPointer, stubSize) : new byte[0];

                if (is64Bit) outputFile = this.Dump64BitPE(processId, dosHeader, dosStub, peHeaderPointer);
                else outputFile = this.Dump32BitPE(processId, dosHeader, dosStub, peHeaderPointer);
            }

            if (outputFile != null)
            {
                if (!isReconstructed)
                {
                    ulong peHeaderPointer = basePointer + (ulong)dosHeader.e_lfanew;
                    ulong sectionHeaderPointer = peHeaderPointer + (ulong)outputFile.GetFirstSectionHeaderOffset();
                    Logger.Log("Parsing {0} Sections...", new object[] { outputFile.Sections.Count });

                    for (int i = 0; i < outputFile.Sections.Count; i++)
                    {
                        NativePEStructs.IMAGE_SECTION_HEADER sectionHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_SECTION_HEADER>(processId, sectionHeaderPointer);
                        outputFile.Sections[i] = new PESection
                        {
                            Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
                            InitialSize = (int)sectionHeader.VirtualSize
                        };
                        sectionHeaderPointer += (ulong)Marshal.SizeOf<NativePEStructs.IMAGE_SECTION_HEADER>();
                    }
                }

                foreach (var section in outputFile.Sections)
                {
                    if (section == null) continue;

                    ulong sectionDataPtr;

                    // CRITICAL FIX:
                    // If we reconstructed the header, it implies the memory is a FLAT MAP (Raw).
                    // In a flat map, the code is at Base + FileOffset (e.g., 0x200).
                    // But our Generated Header says the code is at VirtualAddress 0x2000 (to make the output file valid).
                    // Therefore, when reading from memory, we must ignore the VirtualAddress and use PointerToRawData.
                    if (isReconstructed)
                    {
                        sectionDataPtr = basePointer + (ulong)section.Header.PointerToRawData;
                    }
                    else
                    {
                        // Standard Mapped Image: Code is at Base + RVA (e.g., 0x2000)
                        sectionDataPtr = basePointer + (ulong)section.Header.VirtualAddress;
                    }

                    // For reconstructed files, disable size trimming to ensure we don't cut off tail data
                    this.ReadSectionContent(processId, sectionDataPtr, section, !isReconstructed);
                }

                // Try to Fix .NET Headers
                bool dotNetFound = FixDotNetHeaders(outputFile);

                // Fallback: If we missed metadata and haven't forced reconstruction yet, try forcing it.
                if (!isReconstructed && !dotNetFound)
                {
                    // If it's empty or just looks wrong, retry
                    bool isEmpty = (outputFile.Sections.Count > 0 && (outputFile.Sections[0].Content == null || outputFile.Sections[0].Content.Length == 0));

                    if (isEmpty || true) // Aggressive retry for consistency
                    {
                        Logger.Log("Dump seems invalid or missing Metadata. Retrying with Raw Flat Dump...", Array.Empty<object>());
                        PEFile retryFile;
                        if (DumpProcessImpl(processId, processName, basePointer, imageSize, entryPoint, is64Bit, true, out retryFile))
                        {
                            outputFile = retryFile;
                            return true;
                        }
                    }
                }

                try
                {
                    var modules = this.kernelDriver.GetProcessModules(processId);
                    if (modules.Count > 0)
                    {
                        var reconstructor = new IATReconstructor(this.kernelDriver, processId, modules, is64Bit);
                        reconstructor.FixImports(outputFile);
                    }
                }
                catch { }

                PatchAlignmentForDump(outputFile);
                outputFile.AlignSectionHeaders();
                outputFile.FixPEHeader();

                Logger.Log("Dump Completed !", Array.Empty<object>());
                return true;
            }
            return false;
        }

        private void PatchAlignmentForDump(PEFile peFile)
        {
            // UPDATE: Enforce Standard Alignment (0x2000 Section / 0x200 File)
            if (peFile is PE64File pe64)
            {
                pe64.PEHeader.OptionalHeader.FileAlignment = 0x200;
                pe64.PEHeader.OptionalHeader.SectionAlignment = 0x2000;
            }
            else if (peFile is PE32File pe32)
            {
                pe32.PEHeader.OptionalHeader.FileAlignment = 0x200;
                pe32.PEHeader.OptionalHeader.SectionAlignment = 0x2000;
            }
        }

        private bool FixDotNetHeaders(PEFile peFile)
        {
            if (peFile.Sections.Count == 0 || peFile.Sections[0] == null || peFile.Sections[0].Content == null) return false;

            var mainSection = peFile.Sections[0];
            byte[] data = mainSection.Content;
            long bsjbOffset = -1;

            // Scan for BSJB
            for (int i = 0; i < data.Length - 32; i += 4)
            {
                if (data[i] == 0x42 && data[i + 1] == 0x53 && data[i + 2] == 0x4A && data[i + 3] == 0x42)
                {
                    int versionLen = BitConverter.ToInt32(data, i + 12);
                    if (versionLen > 0 && versionLen < 255 && (i + 16 + versionLen) < data.Length)
                    {
                        bsjbOffset = i;
                        break;
                    }
                }
            }

            if (bsjbOffset == -1) return false;

            Logger.Log("Found .NET Metadata at offset 0x{0:X}. Reconstructing CLR Header...", new object[] { bsjbOffset });

            uint metadataRva = mainSection.Header.VirtualAddress + (uint)bsjbOffset;

            var clrHeader = new NativePEStructs.IMAGE_COR20_HEADER
            {
                cb = 72,
                MajorRuntimeVersion = 2,
                MinorRuntimeVersion = 5,
                Flags = 1,
                EntryPointToken = 0
            };

            clrHeader.MetaData.VirtualAddress = metadataRva;
            clrHeader.MetaData.Size = (uint)(data.Length - bsjbOffset);

            int headerSize = Marshal.SizeOf<NativePEStructs.IMAGE_COR20_HEADER>();
            byte[] headerBytes;
            IntPtr ptr = MarshalUtility.AllocEmptyStruct<NativePEStructs.IMAGE_COR20_HEADER>();
            try
            {
                Marshal.StructureToPtr(clrHeader, ptr, false);
                headerBytes = new byte[headerSize];
                Marshal.Copy(ptr, headerBytes, 0, headerSize);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            peFile.AddSection(".clr", headerBytes,
                (uint)(NativePEStructs.DataSectionFlags.ContentInitializedData |
                       NativePEStructs.DataSectionFlags.MemoryRead));

            var clrSection = peFile.Sections[peFile.Sections.Count - 1];
            uint clrHeaderRva = clrSection.Header.VirtualAddress;

            peFile.SetDataDirectory(14, clrHeaderRva, (uint)headerSize);
            Logger.Log("CLR Header Reconstructed at RVA 0x{0:X}", new object[] { clrHeaderRva });
            return true;
        }

        private bool ReadSectionContent(int processId, ulong sectionPointer, PESection section, bool allowTrim = true)
        {
            int readSize = section.InitialSize;
            if (sectionPointer == 0 || readSize == 0) return true;

            if (readSize <= 100 || !allowTrim)
            {
                section.DataSize = readSize;
                section.Content = this.ReadProcessBytes(processId, sectionPointer, readSize);
                return true;
            }
            else
            {
                this.CalculateRealSectionSize(processId, sectionPointer, section);
                if (section.DataSize != 0)
                {
                    section.Content = this.ReadProcessBytes(processId, sectionPointer, section.DataSize);
                    return true;
                }
            }
            return false;
        }

        private PEFile Dump64BitPE(int processId, NativePEStructs.IMAGE_DOS_HEADER dosHeader, byte[] dosStub, ulong peHeaderPointer)
        {
            NativePEStructs.IMAGE_NT_HEADERS64 peHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_NT_HEADERS64>(processId, peHeaderPointer);
            return peHeader.IsValid ? new PE64File(dosHeader, peHeader, dosStub) : null;
        }

        private PEFile Dump32BitPE(int processId, NativePEStructs.IMAGE_DOS_HEADER dosHeader, byte[] dosStub, ulong peHeaderPointer)
        {
            NativePEStructs.IMAGE_NT_HEADERS32 peHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_NT_HEADERS32>(processId, peHeaderPointer);
            return peHeader.IsValid ? new PE32File(dosHeader, peHeader, dosStub) : null;
        }

        private T ReadProcessStruct<T>(int processId, ulong address) where T : struct
        {
            IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();
            bool flag = this.kernelDriver.CopyVirtualMemory(processId, address, buffer, Marshal.SizeOf<T>());
            T t = flag ? MarshalUtility.GetStructFromMemory<T>(buffer, true) : default(T);
            return t;
        }

        private byte[] ReadProcessBytes(int processId, ulong address, int size)
        {
            IntPtr unmanagedBytePointer = MarshalUtility.AllocZeroFilled(size);
            this.kernelDriver.CopyVirtualMemory(processId, address, unmanagedBytePointer, size);
            byte[] buffer = new byte[size];
            Marshal.Copy(unmanagedBytePointer, buffer, 0, size);
            Marshal.FreeHGlobal(unmanagedBytePointer);
            return buffer;
        }

        private void CalculateRealSectionSize(int processId, ulong sectionPointer, PESection section)
        {
            int readSize = section.InitialSize;
            int currentReadSize = readSize % 100;
            if (currentReadSize == 0) currentReadSize = 100;
            ulong currentOffset = sectionPointer + (ulong)readSize - (ulong)currentReadSize;
            while (currentOffset >= sectionPointer)
            {
                byte[] buffer = this.ReadProcessBytes(processId, currentOffset, currentReadSize);
                int codeByteCount = this.GetInstructionByteCount(buffer);
                if (codeByteCount != 0)
                {
                    currentOffset += (ulong)codeByteCount;
                    if (sectionPointer < currentOffset)
                    {
                        section.DataSize = (int)(currentOffset - sectionPointer);
                        section.DataSize += 4;
                        if (section.InitialSize < section.DataSize) section.DataSize = section.InitialSize;
                    }
                    break;
                }
                currentReadSize = 100;
                currentOffset -= (ulong)currentReadSize;
            }
        }

        private int GetInstructionByteCount(byte[] dataBlock)
        {
            for (int i = dataBlock.Length - 1; i >= 0; i--) { if (dataBlock[i] > 0) return i + 1; }
            return 0;
        }

        private KsDumperDriverInterface kernelDriver;
        internal static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsWow64Process([In] IntPtr process, out bool wow64Process);
        }
    }
}