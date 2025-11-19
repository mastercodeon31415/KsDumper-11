// Relative Path: ProcessSummary.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using KsDumper11.Driver;
using KsDumper11.Utility;

namespace KsDumper11
{
    public class ProcessSummary
    {
        public int ProcessId { get; set; }

        public string ProcessName { get; set; }

        public ulong MainModuleBase { get; set; }

        public string MainModuleFileName { get; set; }

        public uint MainModuleImageSize { get; set; }

        public ulong MainModuleEntryPoint { get; set; }

        public bool IsWOW64 { get; set; }

        // New: Property to store .NET detection status
        public bool IsDotNet { get; set; }

        public static ProcessSummary ProcessSummaryFromID(KsDumperDriverInterface driver, string processName)
        {
            ProcessSummary result = null;
            ProcessSummary[] processes;
            driver.GetProcessSummaryList(out processes);
            bool flag = processes != null;
            if (flag)
            {
                foreach (ProcessSummary process in processes)
                {
                    bool flag2 = process.ProcessName.ToLower().Contains(processName.ToLower());
                    if (flag2)
                    {
                        Logger.Log(process.ProcessName + "      " + processName, Array.Empty<object>());
                        return process;
                    }
                }
            }
            return result;
        }

        // Updated Constructor to include isDotNet
        public ProcessSummary(int processId, ulong mainModuleBase, string mainModuleFileName, uint mainModuleImageSize, ulong mainModuleEntryPoint, bool isWOW64, bool isDotNet = false)
        {
            this.ProcessId = processId;
            this.MainModuleBase = mainModuleBase;
            this.MainModuleFileName = this.FixFileName(mainModuleFileName);
            this.MainModuleImageSize = mainModuleImageSize;
            this.MainModuleEntryPoint = mainModuleEntryPoint;
            this.ProcessName = Path.GetFileName(this.MainModuleFileName);
            this.IsWOW64 = isWOW64;
            this.IsDotNet = isDotNet;
        }

        private string FixFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return "Unknown";

            bool flag = fileName.StartsWith("\\");
            string text;
            if (flag)
            {
                text = fileName;
            }
            else
            {
                StringBuilder sb = new StringBuilder(256);
                int length = WinApi.GetLongPathName(fileName, sb, sb.Capacity);
                bool flag2 = length > sb.Capacity;
                if (flag2)
                {
                    sb.Capacity = length;
                    length = WinApi.GetLongPathName(fileName, sb, sb.Capacity);
                }
                text = sb.ToString();
            }
            return text;
        }

        public static ProcessSummary FromStream(BinaryReader reader)
        {
            // Must match the struct packing in ProcessLister.h
            int pid = reader.ReadInt32();
            ulong baseAddr = reader.ReadUInt64();

            // 256 WCHARS = 512 Bytes
            byte[] nameBytes = reader.ReadBytes(512);
            string name = Encoding.Unicode.GetString(nameBytes).Split(new char[] { '\0' }, 2)[0];

            uint imageSize = reader.ReadUInt32();
            ulong entryPoint = reader.ReadUInt64();
            bool isWow64 = reader.ReadBoolean();
            bool isDotNet = reader.ReadBoolean();

            return new ProcessSummary(pid, baseAddr, name, imageSize, entryPoint, isWow64, isDotNet);
        }
    }
}