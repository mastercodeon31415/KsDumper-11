// Relative Path: KsDumper11\Utility\PathUtils.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace KsDumper11.Utility
{
    public static class PathUtils
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        private static Dictionary<string, string> _deviceMap;

        /// <summary>
        /// Converts a Kernel Device path (\Device\HarddiskVolume3\...) to a DOS path (C:\...).
        /// </summary>
        public static string NormalizePath(string rawPath)
        {
            if (string.IsNullOrEmpty(rawPath)) return "";

            if (rawPath.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            {
                EnsureDeviceMap();

                // Sort keys by length descending to match longest prefix first
                foreach (var kvp in _deviceMap)
                {
                    if (rawPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        return rawPath.Replace(kvp.Key, kvp.Value);
                    }
                }
            }
            return rawPath;
        }

        private static void EnsureDeviceMap()
        {
            if (_deviceMap != null) return;

            _deviceMap = new Dictionary<string, string>();

            // Iterate A-Z
            foreach (string drive in Directory.GetLogicalDrives())
            {
                string driveLetter = drive.Substring(0, 2); // "C:"
                StringBuilder sb = new StringBuilder(512);

                if (QueryDosDevice(driveLetter, sb, sb.Capacity) > 0)
                {
                    string devicePath = sb.ToString();
                    // Store mapping: \Device\HarddiskVolume3 -> C:
                    if (!_deviceMap.ContainsKey(devicePath))
                    {
                        _deviceMap[devicePath] = driveLetter;
                    }
                }
            }
        }
    }
}