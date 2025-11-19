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

        // Cache exports: ModuleName -> Dictionary<RVA, FunctionName>
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

            // Clear cache for new dump session to ensure freshness
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

                    // Basic sanity check: Pointer must be somewhat aligned and non-zero
                    if (ptrVal == 0) continue;

                    var module = FindModuleContainingAddress(ptrVal);
                    if (module.BaseAddress != 0)
                    {
                        uint rva = (uint)(ptrVal - module.BaseAddress);

                        // Resolve Export via Memory Parsing (Fixes Manual Map & Version Mismatch)
                        string exportName = ResolveExport(module, rva);

                        if (!string.IsNullOrEmpty(exportName))
                        {
                            // Use the Name from KERNEL_MODULE_INFO (Handles Manual Maps correctly)
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
            string moduleKey = $"{module.BaseAddress:X}"; // Use BaseAddress as key to avoid name collisions

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
            IntPtr baseAddr = (IntPtr)(long)module.BaseAddress;

            // Read DOS Header
            var dosHeader = ReadStruct<NativePEStructs.IMAGE_DOS_HEADER>(baseAddr);
            if (dosHeader.e_magic[0] != 'M' || dosHeader.e_magic[1] != 'Z') return exports;

            // Read NT Header offset
            IntPtr ntHeaderPtr = baseAddr + dosHeader.e_lfanew;

            // Check Architecture to find Data Directories
            uint exportRva = 0;
            uint exportSize = 0;

            // We rely on _is64Bit flag passed to constructor for the TARGET process architecture
            // However, a module might theoretically be different in WoW64, but typically we follow process arch.

            // Read Signature
            int signature = ReadInt32(ntHeaderPtr);
            if (signature != 0x00004550) return exports; // "PE\0\0"

            // OptionalHeader offset: Signature(4) + FileHeader(20) = 24 bytes
            IntPtr optionalHeaderPtr = ntHeaderPtr + 24;

            ushort magic = ReadUInt16(optionalHeaderPtr);
            bool isMod64 = (magic == 0x20b);

            // DataDirectory Offset
            // PE32: 96 bytes into OptionalHeader
            // PE64: 112 bytes into OptionalHeader
            int dataDirOffset = isMod64 ? 112 : 96;
            IntPtr exportDirEntryPtr = optionalHeaderPtr + dataDirOffset; // Export is index 0

            exportRva = ReadUInt32(exportDirEntryPtr);
            exportSize = ReadUInt32(exportDirEntryPtr + 4);

            if (exportRva == 0 || exportSize == 0) return exports;

            IntPtr exportDirPtr = baseAddr + (int)exportRva;

            // Read Export Directory Table
            // Characteristics (4), TimeDateStamp (4), Major (2), Minor (2), Name (4), Base (4)
            // NumberOfFunctions (4) -> Offset 20
            // NumberOfNames (4)     -> Offset 24
            // AddressOfFunctions (4)-> Offset 28
            // AddressOfNames (4)    -> Offset 32
            // AddressOfNameOrdinals(4)-> Offset 36

            uint numberOfFunctions = ReadUInt32(exportDirPtr + 20);
            uint numberOfNames = ReadUInt32(exportDirPtr + 24);
            uint addressOfFunctionsRva = ReadUInt32(exportDirPtr + 28);
            uint addressOfNamesRva = ReadUInt32(exportDirPtr + 32);
            uint addressOfNameOrdinalsRva = ReadUInt32(exportDirPtr + 36);

            // Pre-calculate pointers
            IntPtr funcTablePtr = baseAddr + (int)addressOfFunctionsRva;
            IntPtr nameTablePtr = baseAddr + (int)addressOfNamesRva;
            IntPtr ordinalTablePtr = baseAddr + (int)addressOfNameOrdinalsRva;

            // Read Ordinals and Names
            // We loop by NumberOfNames because we only care about named exports for IAT reconstruction
            for (uint i = 0; i < numberOfNames; i++)
            {
                // Read Name RVA
                uint nameRva = ReadUInt32(nameTablePtr + (int)(i * 4));
                // Read Ordinal
                ushort ordinal = ReadUInt16(ordinalTablePtr + (int)(i * 2));
                // Read Function RVA
                uint funcRva = ReadUInt32(funcTablePtr + (int)(ordinal * 4));

                // Read Name String
                string name = ReadString(baseAddr + (int)nameRva, 64); // Cap length to avoid massive reads

                // Handle Forwarders
                // If funcRva is within the Export Directory range, it's a forwarder string, not code.
                // We skip forwarders for now as they require recursive resolution which is complex for simple dumping.
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

        // Helper wrappers for driver memory reading
        private T ReadStruct<T>(IntPtr address) where T : struct
        {
            IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();
            if (_driver.CopyVirtualMemory(_processId, address, buffer, Marshal.SizeOf<T>()))
            {
                return MarshalUtility.GetStructFromMemory<T>(buffer, true);
            }
            Marshal.FreeHGlobal(buffer);
            return default(T);
        }

        private uint ReadUInt32(IntPtr address)
        {
            byte[] data = ReadBytes(address, 4);
            if (data.Length == 4) return BitConverter.ToUInt32(data, 0);
            return 0;
        }

        private ushort ReadUInt16(IntPtr address)
        {
            byte[] data = ReadBytes(address, 2);
            if (data.Length == 2) return BitConverter.ToUInt16(data, 0);
            return 0;
        }

        private int ReadInt32(IntPtr address)
        {
            byte[] data = ReadBytes(address, 4);
            if (data.Length == 4) return BitConverter.ToInt32(data, 0);
            return 0;
        }

        private byte[] ReadBytes(IntPtr address, int size)
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

        private string ReadString(IntPtr address, int maxLength)
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

                // Calculate sizes
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
                    if (stringBuffer.Count % 2 != 0) stringBuffer.Add(0); // Align
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
                        stringBuffer.Add(0); stringBuffer.Add(0); // Hint
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

                    // Null terminator for Thunk Array
                    if (_is64Bit) iltBuffer.AddRange(new byte[8]);
                    else iltBuffer.AddRange(new byte[4]);

                    moduleDescriptors.Add(descriptor);
                }

                uint iltBase = (uint)idtSize;
                uint stringsBase = iltBase + (uint)iltBuffer.Count;
                uint iatBase = stringsBase + (uint)stringBuffer.Count;

                // 1. Write IDT
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
                writer.Write(new byte[20]); // Null IDT Entry

                // 2. Write ILT (OriginalFirstThunk)
                var iltBytes = iltBuffer.ToArray();
                PatchThunks(iltBytes, newSectionRva + stringsBase);
                writer.Write(iltBytes);

                // 3. Write Strings
                writer.Write(stringBuffer.ToArray());

                // 4. Write IAT (FirstThunk) - Identical to ILT initially
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