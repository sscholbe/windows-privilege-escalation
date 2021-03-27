using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Escalate {
    static class NTOSKernel {
        // Windows 7 SP 1 x64
        // https://ntdiff.github.io/

        [StructLayout(LayoutKind.Explicit, Size = 0x10)]
        public struct POOL_HEADER {
            [FieldOffset(0x2)]
            public byte BlockSize;
            [FieldOffset(0x4)]
            public uint PoolTag;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x4D0)]
        public unsafe struct EPROCESS {
            [FieldOffset(0x180)]
            public int UniqueProcessId;
            // Can't use string here because the structure would be managed (no use of pointers possible).
            [FieldOffset(0x2E0)]
            public fixed byte ImageFileName[15];
            [FieldOffset(0x2EF)]
            public byte PriorityClass;
            [FieldOffset(0x444)]
            public int ExitStatus;
            [FieldOffset(0x0208)]
            public long Token;
        }
    }
}
