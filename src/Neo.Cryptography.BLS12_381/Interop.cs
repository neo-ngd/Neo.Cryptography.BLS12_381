using System;
using System.Runtime.InteropServices;

namespace Neo.Cryptography.BLS12_381
{
    static class Interop
    {
        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gt_add(IntPtr gt1, IntPtr gt2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gt_mul(IntPtr gt, UInt64 multi);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gt_neg(IntPtr gt);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_add(IntPtr g1_1, IntPtr g1_2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_mul(IntPtr g1, UInt64 multi);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_neg(IntPtr g1);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g2_add(IntPtr g2_1, IntPtr g2_2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g2_mul(IntPtr g2, UInt64 multi);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g2_neg(IntPtr g2);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern void gt_dispose(IntPtr rawPtr);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern void g1_dispose(IntPtr rawPtr);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern void g2_dispose(IntPtr rawPtr);

        [DllImport("Neo_Cryptography_BLS12_381_Native", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr g1_g2_pairing(IntPtr g1, IntPtr g2);
    }
}
