using System;
using System.Runtime.InteropServices;
using KsDumper11.Utility;
using static KsDumper11.Utility.WinApi;

namespace KsDumper11.Driver
{
    public static class Operations
    {
        private static uint CTL_CODE(int deviceType, int function, int method, int access)
        {
            return (uint)((deviceType << 16) | (access << 14) | (function << 2) | method);
        }

        public static readonly uint IO_GET_PROCESS_LIST = Operations.CTL_CODE(WinApi.FILE_DEVICE_UNKNOWN, 0x1724, WinApi.METHOD_BUFFERED, WinApi.FILE_ANY_ACCESS);

        public static readonly uint IO_COPY_MEMORY = Operations.CTL_CODE(WinApi.FILE_DEVICE_UNKNOWN, 0x1725, WinApi.METHOD_BUFFERED, WinApi.FILE_ANY_ACCESS);

        public static readonly uint IO_UNLOAD_DRIVER = Operations.CTL_CODE(WinApi.FILE_DEVICE_UNKNOWN, 0x1726, WinApi.METHOD_BUFFERED, WinApi.FILE_ANY_ACCESS);

        public static readonly uint IO_GET_PROCESS_MODULES = Operations.CTL_CODE(WinApi.FILE_DEVICE_UNKNOWN, 0x1727, WinApi.METHOD_BUFFERED, WinApi.FILE_ANY_ACCESS);

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_PROCESS_LIST_OPERATION
        {
            public ulong bufferAddress;

            public int bufferSize;

            public int processCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_COPY_MEMORY_OPERATION
        {
            public int targetProcessId;

            public ulong targetAddress;

            public ulong bufferAddress;

            public int bufferSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct KERNEL_MODULE_INFO
        {
            public ulong BaseAddress;
            public uint SizeOfImage;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string FullPathName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_GET_MODULES_OPERATION
        {
            public int targetProcessId;
            public ulong bufferAddress;
            public int bufferSize;
            public int moduleCount;
        }
    }
}