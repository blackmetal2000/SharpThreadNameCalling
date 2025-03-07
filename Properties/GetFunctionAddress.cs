using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace pi
{
    class Functions
    {        
        public static IntPtr GetFunctionAddressEx(string dllName, string functionName, IntPtr hProcess, int processPid)
        {
            IntPtr hModule = Win32.GetModuleHandle(dllName);

            if (hModule == IntPtr.Zero)
            {
                throw new Exception($"GetModuleHandle ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            IntPtr procAddress = Win32.GetProcAddress(
                hModule,
                functionName
            );

            if (procAddress == IntPtr.Zero)
            {
                throw new Exception($"GetProcAddress ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            long offset = procAddress.ToInt64() - hModule.ToInt64();

            IntPtr hSnapshot = Win32.CreateToolhelp32Snapshot(
                Win32.SnapshotFlags.Module | Win32.SnapshotFlags.Module32,
                processPid
            );

            if (hSnapshot == IntPtr.Zero)
            {
                throw new Exception($"CreateToolhelp32Snapshot ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            Win32.MODULEENTRY32 me32 = new Win32.MODULEENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(Win32.MODULEENTRY32))
            };
            
            IntPtr baseAddress = IntPtr.Zero;
            if (Win32.Module32First(hSnapshot, ref me32))
            {
                while (Win32.Module32Next(hSnapshot, ref me32))
                {
                    if (string.Compare(me32.szModule, dllName, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        baseAddress = me32.modBaseAddr;
                    }
                }
            }

            IntPtr ApiVirtualAddress = new IntPtr(baseAddress.ToInt64() + offset);

            if (baseAddress == IntPtr.Zero || ApiVirtualAddress == IntPtr.Zero)
            {
                throw new Exception($"Cannot find kernel32.dll BASE ADDRESS! Code: {Marshal.GetLastWin32Error()}");
            }

            return ApiVirtualAddress;
        }
    }
}
