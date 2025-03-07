using System;
using System.Runtime.InteropServices;

namespace pi
{
    public class Wrapper
    {
        private static int HResultFromNt(int ntStatus)
        {
            return ntStatus | 0x10000000;
        }

        public static int MySetThreadDescription(IntPtr hThread, byte[] payload)
        {
            int bufSize = payload.Length;

            IntPtr padding = Marshal.AllocHGlobal(bufSize + sizeof(char));
            try
            {
                for (int i = 0; i < bufSize; i++)
                {
                    Marshal.WriteByte(padding, i, (byte)'A');
                }
                Marshal.WriteInt16(padding, bufSize, 0);

                Win32.UNICODE_STRING destinationString = new Win32.UNICODE_STRING();
                int initStatus = Win32.RtlInitUnicodeStringEx(ref destinationString, padding);
                if (initStatus != 0)
                {
                    throw new Exception($"RtlInitUnicodeStringEx falhou com o status: 0x{initStatus:X}");
                }

                Marshal.Copy(payload, 0, destinationString.Buffer, bufSize);

                int ntStatus = Win32.NtSetInformationThread(
                    hThread,
                    Win32.ThreadInformationClass.ThreadNameInformation,
                    ref destinationString,
                    (uint)Marshal.SizeOf(typeof(Win32.UNICODE_STRING))
                );

                return HResultFromNt(ntStatus);

            }
            finally
            {
                Marshal.FreeHGlobal(padding);
            }
        }
    }
}