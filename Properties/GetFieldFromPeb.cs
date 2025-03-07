using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace pi
{
    class Peb
    {
        public static IntPtr GetFieldFromPeb(IntPtr hProcess)
        {
            Win32.NTSTATUS getPebAddress = Win32.NtQueryInformationProcess(
                hProcess,
                0,
                out Win32.PROCESS_BASIC_INFORMATION pbi,
                Marshal.SizeOf(typeof(Win32.PROCESS_BASIC_INFORMATION)),
                IntPtr.Zero
            );

            if (getPebAddress != Win32.NTSTATUS.Success || pbi.PebBaseAddress == IntPtr.Zero)
            {
                throw new Exception($"NtQueryInformationProcess ERROR! Status: {getPebAddress}");
            }

            IntPtr spareULongsAddress = pbi.PebBaseAddress + 0x340;

            byte[] buffer = new byte[sizeof(uint) * 5];
            bool readMemBool = Win32.ReadProcessMemory(
                hProcess,
                spareULongsAddress,
                buffer,
                buffer.Length,
                out int bytesRead
            );

            if (!readMemBool)
            {
                throw new Exception($"ReadProcessMemory ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            uint[] spareUlongsValues = new uint[5];
            for (int i = 0; i < 5; i++)
            {
                spareUlongsValues[i] = BitConverter.ToUInt32(buffer, i * sizeof(uint));
            }

            Console.WriteLine($"Remote Process's PEB ADDRESS: 000000{pbi.PebBaseAddress.ToString("X")}");
            Console.WriteLine($"Remote Process's SpareULongs ADDRESS: 000000{spareULongsAddress.ToString("X")}\n");

            return spareULongsAddress;
        }
    }
}