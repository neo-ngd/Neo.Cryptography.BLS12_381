using System;
using System.Runtime.InteropServices;

namespace Neo.Cryptography.BLS12_381
{
    public readonly struct GObject
    {
        private const int G1 = 96;
        private const int G2 = 192;
        private const int Gt = 576;

        private readonly byte[] data;

        public int Size => data.Length;

        private GObject(IntPtr ptr, int size)
        {
            data = GC.AllocateUninitializedArray<byte>(size);
            Marshal.Copy(ptr, data, 0, size);
            Marshal.FreeHGlobal(ptr);
        }

        public GObject(byte[] g)
        {
            data = g.Length switch
            {
                G1 or G2 or Gt => g,
                _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
            };
        }

        public unsafe GObject Neg()
        {
            fixed (byte* ptr = data)
                return Size switch
                {
                    G1 => new GObject(Interop.g1_neg(ptr), G1),
                    G2 => new GObject(Interop.g2_neg(ptr), G2),
                    Gt => new GObject(Interop.gt_neg(ptr), Gt),
                    _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
                };
        }

        public unsafe static GObject Add(GObject p1, GObject p2)
        {
            if (p1.Size != p2.Size)
                throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
            fixed (byte* ptr1 = p1.data, ptr2 = p2.data)
                return p1.Size switch
                {
                    G1 => new GObject(Interop.g1_add(ptr1, ptr2), G1),
                    G2 => new GObject(Interop.g2_add(ptr1, ptr2), G2),
                    Gt => new GObject(Interop.gt_add(ptr1, ptr2), Gt),
                    _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
                };
        }

        public unsafe static GObject Mul(GObject p, ulong x)
        {
            fixed (byte* ptr = p.data)
                return p.Size switch
                {
                    G1 => new GObject(Interop.g1_mul(ptr, x), G1),
                    G2 => new GObject(Interop.g2_mul(ptr, x), G2),
                    Gt => new GObject(Interop.gt_mul(ptr, x), Gt),
                    _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
                };
        }

        public unsafe static GObject Pairing(GObject p1, GObject p2)
        {
            if (p1.Size != G1 || p2.Size != G2)
                throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
            fixed (byte* ptr1 = p1.data, ptr2 = p2.data)
                return new(Interop.g1_g2_pairing(ptr1, ptr2), Gt);
        }

        public byte[] ToByteArray()
        {
            return data;
        }

        public static implicit operator GObject(byte[] data) => new(data);
    }
}
