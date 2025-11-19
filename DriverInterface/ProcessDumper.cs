// Relative Path: ProcessDumper.cs
using KsDumper11.Driver;
using KsDumper11.PE;
using KsDumper11.Utility;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
            // Native process object wrapper
            return DumpProcessImpl(processSummary.Id, processSummary.ProcessName, processSummary.MainModule.BaseAddress, !IsWin64Emulator(processSummary), out outputFile);
        }

        public bool DumpProcess(ProcessSummary processSummary, out PEFile outputFile)
        {
            // Custom ProcessSummary wrapper
            return DumpProcessImpl(processSummary.ProcessId, processSummary.ProcessName, (IntPtr)((long)processSummary.MainModuleBase), !processSummary.IsWOW64, out outputFile);
        }

        private bool DumpProcessImpl(int processId, string processName, IntPtr basePointer, bool is64Bit, out PEFile outputFile)
        {
            NativePEStructs.IMAGE_DOS_HEADER dosHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_DOS_HEADER>(processId, basePointer);
            outputFile = null;
            Logger.SkipLine();
            Logger.Log("Targeting Process: {0} ({1})", new object[] { processName, processId });
            bool isValid = dosHeader.IsValid;
            if (isValid)
            {
                IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;
                Logger.Log("PE Header Found: 0x{0:x8}", new object[] { peHeaderPointer.ToInt64() });
                IntPtr dosStubPointer = basePointer + Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>();
                byte[] dosStub = this.ReadProcessBytes(processId, dosStubPointer, dosHeader.e_lfanew - Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>());

                PEFile peFile;
                if (is64Bit)
                {
                    peFile = this.Dump64BitPE(processId, dosHeader, dosStub, peHeaderPointer);
                }
                else
                {
                    peFile = this.Dump32BitPE(processId, dosHeader, dosStub, peHeaderPointer);
                }

                bool flag2 = peFile != null;
                if (flag2)
                {
                    IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();
                    Logger.Log("Header is valid ({0}) !", new object[] { peFile.Type });
                    Logger.Log("Parsing {0} Sections...", new object[] { peFile.Sections.Count });

                    for (int i = 0; i < peFile.Sections.Count; i++)
                    {
                        NativePEStructs.IMAGE_SECTION_HEADER sectionHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_SECTION_HEADER>(processId, sectionHeaderPointer);

                        // Update existing section entry
                        peFile.Sections[i] = new PESection
                        {
                            Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
                            InitialSize = (int)sectionHeader.VirtualSize
                        };

                        this.ReadSectionContent(processId, new IntPtr(basePointer.ToInt64() + (long)((ulong)sectionHeader.VirtualAddress)), peFile.Sections[i]);
                        sectionHeaderPointer += Marshal.SizeOf<NativePEStructs.IMAGE_SECTION_HEADER>();
                    }

                    Logger.Log("Aligning Sections...", Array.Empty<object>());
                    peFile.AlignSectionHeaders();

                    // ---------------------------------------------------------
                    // IAT Reconstruction
                    // ---------------------------------------------------------
                    try
                    {
                        Logger.Log("Getting Module List for IAT Reconstruction...", Array.Empty<object>());
                        var modules = this.kernelDriver.GetProcessModules(processId);

                        if (modules.Count > 0)
                        {
                            // Pass driver and processId to allow memory reading of exports
                            var reconstructor = new IATReconstructor(this.kernelDriver, processId, modules, is64Bit);
                            bool fixedImports = reconstructor.FixImports(peFile);
                            if (fixedImports)
                            {
                                Logger.Log("IAT Reconstructed and New Section Added.", Array.Empty<object>());
                            }
                            else
                            {
                                Logger.Log("IAT Reconstruction attempted but no imports found or fix unneeded.", Array.Empty<object>());
                            }
                        }
                        else
                        {
                            Logger.Log("Failed to enumerate modules from Kernel. Skipping IAT fix.", Array.Empty<object>());
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Error during IAT Reconstruction: " + ex.Message, Array.Empty<object>());
                    }
                    // ---------------------------------------------------------

                    Logger.Log("Fixing PE Header...", Array.Empty<object>());
                    peFile.FixPEHeader();
                    Logger.Log("Dump Completed !", Array.Empty<object>());
                    outputFile = peFile;
                    return true;
                }
                Logger.Log("Bad PE Header !", Array.Empty<object>());
            }
            return false;
        }

        private PEFile Dump64BitPE(int processId, NativePEStructs.IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            NativePEStructs.IMAGE_NT_HEADERS64 peHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_NT_HEADERS64>(processId, peHeaderPointer);
            bool isValid = peHeader.IsValid;
            PEFile pefile;
            if (isValid)
            {
                pefile = new PE64File(dosHeader, peHeader, dosStub);
            }
            else
            {
                pefile = null;
            }
            return pefile;
        }

        private PEFile Dump32BitPE(int processId, NativePEStructs.IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            NativePEStructs.IMAGE_NT_HEADERS32 peHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_NT_HEADERS32>(processId, peHeaderPointer);
            bool isValid = peHeader.IsValid;
            PEFile pefile;
            if (isValid)
            {
                pefile = new PE32File(dosHeader, peHeader, dosStub);
            }
            else
            {
                pefile = null;
            }
            return pefile;
        }

        private T ReadProcessStruct<T>(int processId, IntPtr address) where T : struct
        {
            IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();
            bool flag = this.kernelDriver.CopyVirtualMemory(processId, address, buffer, Marshal.SizeOf<T>());
            T t;
            if (flag)
            {
                t = MarshalUtility.GetStructFromMemory<T>(buffer, true);
            }
            else
            {
                t = default(T);
            }
            return t;
        }

        private bool ReadSectionContent(int processId, IntPtr sectionPointer, PESection section)
        {
            int readSize = section.InitialSize;
            bool flag = sectionPointer == IntPtr.Zero || readSize == 0;
            bool flag2;
            if (flag)
            {
                flag2 = true;
            }
            else
            {
                bool flag3 = readSize <= 100;
                if (flag3)
                {
                    section.DataSize = readSize;
                    section.Content = this.ReadProcessBytes(processId, sectionPointer, readSize);
                    flag2 = true;
                }
                else
                {
                    this.CalculateRealSectionSize(processId, sectionPointer, section);
                    bool flag4 = section.DataSize != 0;
                    if (flag4)
                    {
                        section.Content = this.ReadProcessBytes(processId, sectionPointer, section.DataSize);
                        flag2 = true;
                    }
                    else
                    {
                        flag2 = false;
                    }
                }
            }
            return flag2;
        }

        private byte[] ReadProcessBytes(int processId, IntPtr address, int size)
        {
            IntPtr unmanagedBytePointer = MarshalUtility.AllocZeroFilled(size);
            this.kernelDriver.CopyVirtualMemory(processId, address, unmanagedBytePointer, size);
            byte[] buffer = new byte[size];
            Marshal.Copy(unmanagedBytePointer, buffer, 0, size);
            Marshal.FreeHGlobal(unmanagedBytePointer);
            return buffer;
        }

        private void CalculateRealSectionSize(int processId, IntPtr sectionPointer, PESection section)
        {
            int readSize = section.InitialSize;
            int currentReadSize = readSize % 100;
            bool flag = currentReadSize == 0;
            if (flag)
            {
                currentReadSize = 100;
            }
            IntPtr currentOffset = sectionPointer + readSize - currentReadSize;
            while (currentOffset.ToInt64() >= sectionPointer.ToInt64())
            {
                byte[] buffer = this.ReadProcessBytes(processId, currentOffset, currentReadSize);
                int codeByteCount = this.GetInstructionByteCount(buffer);
                bool flag2 = codeByteCount != 0;
                if (flag2)
                {
                    currentOffset += codeByteCount;
                    bool flag3 = sectionPointer.ToInt64() < currentOffset.ToInt64();
                    if (flag3)
                    {
                        section.DataSize = (int)(currentOffset.ToInt64() - sectionPointer.ToInt64());
                        section.DataSize += 4;
                        bool flag4 = section.InitialSize < section.DataSize;
                        if (flag4)
                        {
                            section.DataSize = section.InitialSize;
                        }
                    }
                    break;
                }
                currentReadSize = 100;
                currentOffset -= currentReadSize;
            }
        }

        private int GetInstructionByteCount(byte[] dataBlock)
        {
            for (int i = dataBlock.Length - 1; i >= 0; i--)
            {
                bool flag = dataBlock[i] > 0;
                if (flag)
                {
                    return i + 1;
                }
            }
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