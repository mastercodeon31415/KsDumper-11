// Relative Path: KsDumper11\Utility\DotNetResolver.cs
using System;
using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using KsDumper11.Driver;
using System.Runtime.InteropServices;
using System.Text;

namespace KsDumper11.Utility
{
    public struct DotNetInfo
    {
        public string Name;
        public string Version;
        public bool IsValid => !string.IsNullOrEmpty(Name);
    }

    public static class DotNetResolver
    {
        public static DotNetInfo GetDotNetInfo(KsDumperDriverInterface driver, int pid, ulong baseAddress, uint size)
        {
            var info = new DotNetInfo();
            if (size == 0 || size > 100 * 1024 * 1024) return info;

            // Strategy 1: PEReader (Standard)
            try
            {
                using (var stream = new RemoteProcessStream(driver, pid, baseAddress, (long)size))
                using (var peReader = new PEReader(stream, PEStreamOptions.IsLoadedImage | PEStreamOptions.PrefetchMetadata))
                {
                    if (peReader.HasMetadata)
                    {
                        var mdReader = peReader.GetMetadataReader();
                        if (mdReader.IsAssembly)
                        {
                            var asmDef = mdReader.GetAssemblyDefinition();
                            info.Name = mdReader.GetString(asmDef.Name);
                            info.Version = mdReader.MetadataVersion;
                            return info;
                        }
                    }
                }
            }
            catch { }

            // Strategy 2: Raw Memory Scan (Packer/Obfuscator fallback)
            try
            {
                byte[] buffer = new byte[size];
                IntPtr unmanaged = MarshalUtility.AllocZeroFilled((int)size);

                if (driver.CopyVirtualMemory(pid, baseAddress, unmanaged, (int)size))
                {
                    Marshal.Copy(unmanaged, buffer, 0, (int)size);
                    Marshal.FreeHGlobal(unmanaged);

                    // Scan for BSJB signature (Metadata Root)
                    for (int i = 0; i < buffer.Length - 32; i += 4)
                    {
                        if (buffer[i] == 0x42 && buffer[i + 1] == 0x53 && buffer[i + 2] == 0x4A && buffer[i + 3] == 0x42)
                        {
                            // Found 'BSJB'.
                            // Version string starts at offset 12 relative to BSJB
                            // Structure: Signature(4), Major(2), Minor(2), Reserved(4), VersionLen(4), VersionString(x)
                            int verLenOffset = i + 12;
                            if (verLenOffset + 4 < buffer.Length)
                            {
                                int versionLength = BitConverter.ToInt32(buffer, verLenOffset);
                                if (versionLength > 0 && versionLength < 255 && verLenOffset + 4 + versionLength < buffer.Length)
                                {
                                    string ver = Encoding.UTF8.GetString(buffer, verLenOffset + 4, versionLength).Trim('\0');
                                    info.Version = ver;

                                    // Try to get Name via MetadataReader at this offset
                                    try
                                    {
                                        unsafe
                                        {
                                            fixed (byte* ptr = buffer)
                                            {
                                                var metadataReader = new MetadataReader(ptr + i, buffer.Length - i);
                                                if (metadataReader.IsAssembly)
                                                {
                                                    var asmDef = metadataReader.GetAssemblyDefinition();
                                                    info.Name = metadataReader.GetString(asmDef.Name);
                                                    return info;
                                                }
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Marshal.FreeHGlobal(unmanaged);
                }
            }
            catch { }

            return info;
        }

        // Backward compatibility helper
        public static string GetAssemblyName(KsDumperDriverInterface driver, int pid, ulong baseAddress, uint size)
        {
            return GetDotNetInfo(driver, pid, baseAddress, size).Name;
        }
    }
}