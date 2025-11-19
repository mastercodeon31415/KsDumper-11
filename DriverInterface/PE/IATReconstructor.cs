// Relative Path: PE\IATReconstructor.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumper11.Driver;
using KsDumper11.Utility;

namespace KsDumper11.PE
{
    public class IATReconstructor
    {
        private readonly KsDumperDriverInterface _driver;
        private readonly int _processId;
        private readonly List<Operations.KERNEL_MODULE_INFO> _modules;
        private readonly bool _is64Bit;

        private static Dictionary<string, Dictionary<uint, string>> _exportCache = new Dictionary<string, Dictionary<uint, string>>();

        public IATReconstructor(KsDumperDriverInterface driver, int processId, List<Operations.KERNEL_MODULE_INFO> modules, bool is64Bit)
        {
            _driver = driver;
            _processId = processId;
            _modules = modules;
            _is64Bit = is64Bit;
        }

        public bool FixImports(PEFile dumpedPe)
        {
            Logger.Log("Starting IAT Reconstruction...");
            _exportCache.Clear();

            var importedFunctions = ScanForImports(dumpedPe);

            if (importedFunctions.Count == 0)
            {
                Logger.Log("No imports found to reconstruct.");
                return false;
            }

            Logger.Log($"Found {importedFunctions.Sum(x => x.Value.Count)} potential imports across {importedFunctions.Count} modules.");

            return RebuildImportTable(dumpedPe, importedFunctions);
        }

        private Dictionary<string, List<ImportEntry>> ScanForImports(PEFile pe)
        {
            var results = new Dictionary<string, List<ImportEntry>>();
            int ptrSize = _is64Bit ? 8 : 4;

            foreach (var section in pe.Sections)
            {
                if (section.Content == null || section.Content.Length == 0) continue;

                for (int i = 0; i < section.Content.Length - ptrSize; i += 4)
                {
                    ulong ptrVal = 0;
                    if (_is64Bit)
                        ptrVal = BitConverter.ToUInt64(section.Content, i);
                    else
                        ptrVal = BitConverter.ToUInt32(section.Content, i);

                    if (ptrVal == 0) continue;

                    var module = FindModuleContainingAddress(ptrVal);
                    if (module.BaseAddress != 0)
                    {
                        uint rva = (uint)(ptrVal - module.BaseAddress);
                        string exportName = ResolveExport(module, rva);

                        if (!string.IsNullOrEmpty(exportName))
                        {
                            string modName = Path.GetFileName(module.FullPathName);
                            if (string.IsNullOrEmpty(modName)) modName = $"Module_{module.BaseAddress:X}";

                            if (!results.ContainsKey(modName))
                                results[modName] = new List<ImportEntry>();

                            if (!results[modName].Any(x => x.Name == exportName))
                            {
                                results[modName].Add(new ImportEntry
                                {
                                    Name = exportName,
                                    RvaInModule = rva
                                });
                            }
                        }
                    }
                }
            }
            return results;
        }

        private Operations.KERNEL_MODULE_INFO FindModuleContainingAddress(ulong address)
        {
            foreach (var mod in _modules)
            {
                if (address >= mod.BaseAddress && address < (mod.BaseAddress + mod.SizeOfImage))
                {
                    return mod;
                }
            }
            return new Operations.KERNEL_MODULE_INFO();
        }

        private string ResolveExport(Operations.KERNEL_MODULE_INFO module, uint rva)
        {
            string moduleKey = $"{module.BaseAddress:X}";

            if (!_exportCache.ContainsKey(moduleKey))
            {
                var exports = ParseExportsFromMemory(module);
                _exportCache[moduleKey] = exports;
            }

            if (_exportCache[moduleKey].TryGetValue(rva, out string funcName))
            {
                return funcName;
            }

            return null;
        }

        private Dictionary<uint, string> ParseExportsFromMemory(Operations.KERNEL_MODULE_INFO module)
        {
            var exports = new Dictionary<uint, string>();
            // CHANGED: Use ulong for base address to avoid 32-bit overflow
            ulong baseAddr = module.BaseAddress;

            var dosHeader = ReadStruct<NativePEStructs.IMAGE_DOS_HEADER>(baseAddr);
            if (dosHeader.e_magic[0] != 'M' || dosHeader.e_magic[1] != 'Z') return exports;

            // Use ulong arithmetic
            ulong ntHeaderPtr = baseAddr + (ulong)dosHeader.e_lfanew;

            int signature = ReadInt32(ntHeaderPtr);
            if (signature != 0x00004550) return exports;

            ulong optionalHeaderPtr = ntHeaderPtr + 24;

            ushort magic = ReadUInt16(optionalHeaderPtr);
            bool isMod64 = (magic == 0x20b);

            int dataDirOffset = isMod64 ? 112 : 96;
            ulong exportDirEntryPtr = optionalHeaderPtr + (ulong)dataDirOffset;

            uint exportRva = ReadUInt32(exportDirEntryPtr);
            uint exportSize = ReadUInt32(exportDirEntryPtr + 4);

            if (exportRva == 0 || exportSize == 0) return exports;

            ulong exportDirPtr = baseAddr + exportRva;

            uint numberOfFunctions = ReadUInt32(exportDirPtr + 20);
            uint numberOfNames = ReadUInt32(exportDirPtr + 24);
            uint addressOfFunctionsRva = ReadUInt32(exportDirPtr + 28);
            uint addressOfNamesRva = ReadUInt32(exportDirPtr + 32);
            uint addressOfNameOrdinalsRva = ReadUInt32(exportDirPtr + 36);

            ulong funcTablePtr = baseAddr + addressOfFunctionsRva;
            ulong nameTablePtr = baseAddr + addressOfNamesRva;
            ulong ordinalTablePtr = baseAddr + addressOfNameOrdinalsRva;

            for (uint i = 0; i < numberOfNames; i++)
            {
                uint nameRva = ReadUInt32(nameTablePtr + (i * 4));
                ushort ordinal = ReadUInt16(ordinalTablePtr + (i * 2));
                uint funcRva = ReadUInt32(funcTablePtr + ((ulong)ordinal * 4));

                string name = ReadString(baseAddr + nameRva, 64);

                bool isForwarder = (funcRva >= exportRva && funcRva < (exportRva + exportSize));

                if (!string.IsNullOrEmpty(name) && !isForwarder)
                {
                    if (!exports.ContainsKey(funcRva))
                    {
                        exports.Add(funcRva, name);
                    }
                }
            }

            return exports;
        }

        // CHANGED: All Read helpers now take ulong address
        private T ReadStruct<T>(ulong address) where T : struct
        {
            IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();
            if (_driver.CopyVirtualMemory(_processId, address, buffer, Marshal.SizeOf<T>()))
            {
                return MarshalUtility.GetStructFromMemory<T>(buffer, true);
            }
            Marshal.FreeHGlobal(buffer);
            return default(T);
        }

        private uint ReadUInt32(ulong address)
        {
            byte[] data = ReadBytes(address, 4);
            if (data.Length == 4) return BitConverter.ToUInt32(data, 0);
            return 0;
        }

        private ushort ReadUInt16(ulong address)
        {
            byte[] data = ReadBytes(address, 2);
            if (data.Length == 2) return BitConverter.ToUInt16(data, 0);
            return 0;
        }

        private int ReadInt32(ulong address)
        {
            byte[] data = ReadBytes(address, 4);
            if (data.Length == 4) return BitConverter.ToInt32(data, 0);
            return 0;
        }

        private byte[] ReadBytes(ulong address, int size)
        {
            IntPtr buffer = MarshalUtility.AllocZeroFilled(size);
            if (_driver.CopyVirtualMemory(_processId, address, buffer, size))
            {
                byte[] res = new byte[size];
                Marshal.Copy(buffer, res, 0, size);
                Marshal.FreeHGlobal(buffer);
                return res;
            }
            Marshal.FreeHGlobal(buffer);
            return new byte[0];
        }

        private string ReadString(ulong address, int maxLength)
        {
            byte[] buffer = ReadBytes(address, maxLength);
            int nullIdx = Array.IndexOf(buffer, (byte)0);
            if (nullIdx >= 0)
            {
                return Encoding.ASCII.GetString(buffer, 0, nullIdx);
            }
            return Encoding.ASCII.GetString(buffer);
        }

        private bool RebuildImportTable(PEFile pe, Dictionary<string, List<ImportEntry>> imports)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                uint newSectionRva = pe.GetNextSectionRva();
                int idtSize = (imports.Count + 1) * 20;

                var moduleDescriptors = new List<ImportDescriptor>();
                var iltBuffer = new List<byte>();
                var stringBuffer = new List<byte>();
                var stringOffsets = new Dictionary<string, uint>();

                Func<string, uint> addString = (s) => {
                    if (stringOffsets.ContainsKey(s)) return stringOffsets[s];
                    uint off = (uint)stringBuffer.Count;
                    stringBuffer.AddRange(Encoding.ASCII.GetBytes(s));
                    stringBuffer.Add(0);
                    if (stringBuffer.Count % 2 != 0) stringBuffer.Add(0);
                    stringOffsets[s] = off;
                    return off;
                };

                foreach (var mod in imports)
                {
                    var descriptor = new ImportDescriptor();
                    descriptor.NameOffsetInStrings = addString(mod.Key);
                    descriptor.IltOffset = (uint)iltBuffer.Count;

                    foreach (var func in mod.Value)
                    {
                        uint hintNameRva = (uint)stringBuffer.Count;
                        stringBuffer.Add(0); stringBuffer.Add(0);
                        stringBuffer.AddRange(Encoding.ASCII.GetBytes(func.Name));
                        stringBuffer.Add(0);
                        if (stringBuffer.Count % 2 != 0) stringBuffer.Add(0);

                        if (_is64Bit)
                        {
                            ulong thunk = hintNameRva;
                            iltBuffer.AddRange(BitConverter.GetBytes(thunk));
                        }
                        else
                        {
                            uint thunk = hintNameRva;
                            iltBuffer.AddRange(BitConverter.GetBytes(thunk));
                        }
                    }

                    if (_is64Bit) iltBuffer.AddRange(new byte[8]);
                    else iltBuffer.AddRange(new byte[4]);

                    moduleDescriptors.Add(descriptor);
                }

                uint iltBase = (uint)idtSize;
                uint stringsBase = iltBase + (uint)iltBuffer.Count;
                uint iatBase = stringsBase + (uint)stringBuffer.Count;

                foreach (var desc in moduleDescriptors)
                {
                    uint originalFirstThunkRva = newSectionRva + iltBase + desc.IltOffset;
                    uint nameRva = newSectionRva + stringsBase + desc.NameOffsetInStrings;
                    uint firstThunkRva = newSectionRva + iatBase + desc.IltOffset;

                    writer.Write(originalFirstThunkRva);
                    writer.Write((uint)0);
                    writer.Write((uint)0);
                    writer.Write(nameRva);
                    writer.Write(firstThunkRva);
                }
                writer.Write(new byte[20]);

                var iltBytes = iltBuffer.ToArray();
                PatchThunks(iltBytes, newSectionRva + stringsBase);
                writer.Write(iltBytes);

                writer.Write(stringBuffer.ToArray());

                writer.Write(iltBytes);

                writer.Flush();
                byte[] newSectionData = ms.ToArray();

                pe.AddSection(".idata", newSectionData,
                    (uint)(NativePEStructs.DataSectionFlags.MemoryRead |
                           NativePEStructs.DataSectionFlags.MemoryWrite |
                           NativePEStructs.DataSectionFlags.ContentInitializedData));

                pe.SetDataDirectory(NativePEStructs.IMAGE_DIRECTORY_ENTRY_IMPORT, newSectionRva, (uint)idtSize);
                pe.SetDataDirectory(NativePEStructs.IMAGE_DIRECTORY_ENTRY_IAT, newSectionRva + iatBase, (uint)iltBytes.Length);

                return true;
            }
        }

        private void PatchThunks(byte[] bytes, uint baseRva)
        {
            int step = _is64Bit ? 8 : 4;
            for (int i = 0; i < bytes.Length; i += step)
            {
                if (_is64Bit)
                {
                    ulong val = BitConverter.ToUInt64(bytes, i);
                    if (val != 0)
                    {
                        val += baseRva;
                        Array.Copy(BitConverter.GetBytes(val), 0, bytes, i, 8);
                    }
                }
                else
                {
                    uint val = BitConverter.ToUInt32(bytes, i);
                    if (val != 0)
                    {
                        val += baseRva;
                        Array.Copy(BitConverter.GetBytes(val), 0, bytes, i, 4);
                    }
                }
            }
        }

        private struct ImportEntry
        {
            public string Name;
            public uint RvaInModule;
        }

        private struct ImportDescriptor
        {
            public uint NameOffsetInStrings;
            public uint IltOffset;
        }
    }
}