// Relative Path: KsDumper11\Utility\RemoteProcessStream.cs
using KsDumper11.Driver;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace KsDumper11.Utility
{
    public class RemoteProcessStream : Stream
    {
        private readonly KsDumperDriverInterface _driver;
        private readonly int _processId;
        private readonly ulong _baseAddress;
        private readonly long _length;
        private long _position;

        public RemoteProcessStream(KsDumperDriverInterface driver, int processId, ulong baseAddress, long length)
        {
            _driver = driver;
            _processId = processId;
            _baseAddress = baseAddress;
            _length = length;
            _position = 0;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _length;

        public override long Position
        {
            get => _position;
            set
            {
                if (value < 0 || value > _length)
                    throw new ArgumentOutOfRangeException(nameof(value));
                _position = value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0) throw new ArgumentOutOfRangeException();
            if (buffer.Length - offset < count) throw new ArgumentException("Invalid buffer offset/count");

            long remaining = _length - _position;
            if (remaining <= 0) return 0;

            int toRead = (int)Math.Min(count, remaining);

            // Allocate unmanaged memory for the driver to copy into
            IntPtr unmanagedBuffer = MarshalUtility.AllocZeroFilled(toRead);

            bool success = _driver.CopyVirtualMemory(
                _processId,
                _baseAddress + (ulong)_position,
                unmanagedBuffer,
                toRead
            );

            if (success)
            {
                Marshal.Copy(unmanagedBuffer, buffer, offset, toRead);
                _position += toRead;
                Marshal.FreeHGlobal(unmanagedBuffer);
                return toRead;
            }
            else
            {
                Marshal.FreeHGlobal(unmanagedBuffer);
                return 0;
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long newPos = _position;
            switch (origin)
            {
                case SeekOrigin.Begin:
                    newPos = offset;
                    break;
                case SeekOrigin.Current:
                    newPos += offset;
                    break;
                case SeekOrigin.End:
                    newPos = _length + offset;
                    break;
            }

            if (newPos < 0 || newPos > _length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            _position = newPos;
            return _position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
    }
}