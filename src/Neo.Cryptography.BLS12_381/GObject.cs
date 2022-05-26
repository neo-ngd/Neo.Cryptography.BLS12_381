using System;
using System.Runtime.InteropServices;

namespace Neo.Cryptography.BLS12_381
{
    public class GObject
    {
        private const int G1 = 96;
        private const int G2 = 192;
        private const int Gt = 576;

        private readonly IntPtr ptr;
        private readonly int size;

        private GObject(IntPtr ptr, int size)
        {
            this.ptr = ptr;
            this.size = size;
        }

        public GObject(byte[] g)
        {
            size = g.Length;
            if (size is G1 or G2 or Gt)
            {
                ptr = Marshal.AllocHGlobal(size);
                Marshal.Copy(g, 0, ptr, size);
            }
            else throw new Exception($"Bls12381 operation fault, type:format, error:valid point length");
        }

        ~GObject()
        {
            Marshal.FreeHGlobal(ptr);
        }

        public GObject Neg()
        {
            return size switch
            {
                G1 => new GObject(Interop.g1_neg(ptr), G1),
                G2 => new GObject(Interop.g2_neg(ptr), G2),
                Gt => new GObject(Interop.gt_neg(ptr), Gt),
                _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
            };
        }

        public static GObject Add(GObject p1, GObject p2)
        {
            if (p1.size != p2.size)
            {
                throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
            }
            return p1.size switch
            {
                G1 => new GObject(Interop.g1_add(p1.ptr, p2.ptr), G1),
                G2 => new GObject(Interop.g2_add(p1.ptr, p2.ptr), G2),
                Gt => new GObject(Interop.gt_add(p1.ptr, p2.ptr), Gt),
                _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
            };
        }

        public static GObject Mul(GObject p, ulong x)
        {
            return p.size switch
            {
                G1 => new GObject(Interop.g1_mul(p.ptr, x), G1),
                G2 => new GObject(Interop.g2_mul(p.ptr, x), G2),
                Gt => new GObject(Interop.gt_mul(p.ptr, x), Gt),
                _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
            };
        }

        public static GObject Pairing(GObject p1, GObject p2)
        {
            if (p1.size != G1 || p2.size != G2)
            {
                throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
            }
            return new(Interop.g1_g2_pairing(p1.ptr, p2.ptr), Gt);
        }

        public byte[] ToByteArray()
        {
            byte[] buffer = GC.AllocateUninitializedArray<byte>(size);
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
            return buffer;
        }
    }
}
