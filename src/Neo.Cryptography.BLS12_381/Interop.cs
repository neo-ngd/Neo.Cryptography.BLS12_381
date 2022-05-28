using System;
using System.Runtime.InteropServices;

namespace Neo.Cryptography.BLS12_381
{
    static unsafe class Interop
    {
        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gt_add(byte* gt1, byte* gt2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gt_mul(byte* gt, ulong multi);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gt_neg(byte* gt);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_add(byte* g1_1, byte* g1_2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_mul(byte* g1, ulong multi);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_neg(byte* g1);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g2_add(byte* g2_1, byte* g2_2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g2_mul(byte* g2, ulong multi);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g2_neg(byte* g2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_g2_pairing(byte* g1, byte* g2);
    }
}
