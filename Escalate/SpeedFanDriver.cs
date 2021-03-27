using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Escalate {
    class SpeedFanDriver : IDisposable {
        private SafeFileHandle device;

        #region WinAPI
        private const uint GenericRead = 0x80000000, FileAttributeNormal = 0x80;

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern SafeFileHandle CreateFileA(
           string filename,
           uint access,
           uint share,
           IntPtr securityAttributes,
           FileMode creationDisposition,
           uint flagsAndAttributes,
           IntPtr templateFile
           );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static unsafe extern bool DeviceIoControl(
           SafeFileHandle device,
           uint controlCode,
           void* inBuffer,
           int inBufferSize,
           void* outBuffer,
           int outBufferSize,
           ref int bytesReturned,
           IntPtr overlapped
           );
        #endregion

        public SpeedFanDriver() {
            device = CreateFileA(@"\\.\\speedfan", GenericRead, 0, IntPtr.Zero, FileMode.Open, FileAttributeNormal, IntPtr.Zero);
            if (device.IsInvalid) {
                throw new NotSupportedException("SpeedFan driver is not installed.");
            }
        }

        public void Dispose() {
            if (!device.IsInvalid && !device.IsClosed) {
                device.Close();
            }
        }

        public void ReadMemory(IntPtr address, IntPtr buffer, int size) {
            // IOCTL_PHYMEM_READ
            int returned = 0;       
            unsafe {
                if (!DeviceIoControl(device, 0x9C402428, &address, IntPtr.Size, buffer.ToPointer(), size, ref returned, IntPtr.Zero) || returned != size) {
                    throw new NotSupportedException("Could not read from memory.");
                }
            }
        }

        public T ReadMemory<T>(IntPtr address) {
            int size = Marshal.SizeOf<T>();
            IntPtr data = Marshal.AllocHGlobal(size);
            try {
                ReadMemory(address, data, size);
                return Marshal.PtrToStructure<T>(data);
            } finally {
                Marshal.FreeHGlobal(data);
            }
        }

        public void WriteMemory<T>(IntPtr address, T value) {
            int size = Marshal.SizeOf<T>();
            IntPtr data = Marshal.AllocHGlobal(IntPtr.Size + size);
            try {
                // The driver packet consists of the physical address followed by the data.
                Marshal.StructureToPtr(address, data, false);
                Marshal.StructureToPtr(value, data + IntPtr.Size, false);

                // IOCTL_PHYMEM_WRITE
                int returned = 0;
                unsafe {
                    if (!DeviceIoControl(device, 0x9C40242C, data.ToPointer(), IntPtr.Size + size, null, 0, ref returned, IntPtr.Zero)) {
                        throw new NotSupportedException("Could not write to memory.");
                    }
                }
            } finally {
                Marshal.FreeHGlobal(data);
            }
        }
    }
}
