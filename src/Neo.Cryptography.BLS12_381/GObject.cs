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
        private readonly int type;

        private GObject(IntPtr ptr, int t)
        {
            this.ptr = ptr;
            this.type = t;
        }

        public GObject(byte[] g)
        {
            int len = g.Length;
            if (len is G1 or G2 or Gt)
            {
                IntPtr tmp = Marshal.AllocHGlobal(len);
                Marshal.Copy(g, 0, tmp, len);
                this.type = len;
                this.ptr = tmp;
            }
            else throw new Exception($"Bls12381 operation falut,type:format,error:valid point length");
        }

        ~GObject()
        {
            try
            {
                switch (type)
                {
                    case G1:
                        Interop.g1_dispose(ptr);
                        break;
                    case G2:
                        Interop.g2_dispose(ptr);
                        break;
                    case Gt:
                        Interop.gt_dispose(ptr);
                        break;
                    default:
                        throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
                }
            }
            catch (Exception)
            {
                throw new Exception($"Bls12381 operation falut,type:format,error:dispose failed");
            }
        }

        public GObject Neg()
        {
            GObject G = type switch
            {
                G1 => new GObject(Interop.g1_neg(ptr), G1),
                G2 => new GObject(Interop.g2_neg(ptr), G2),
                Gt => new GObject(Interop.gt_neg(ptr), Gt),
                _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
            };
            return G;
        }

        public static GObject Add(GObject p1, GObject p2)
        {
            if (p1.type != p2.type)
            {
                throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
            }
            return p1.type switch
            {
                G1 => new GObject(Interop.g1_add(p1.ptr, p2.ptr), G1),
                G2 => new GObject(Interop.g2_add(p1.ptr, p2.ptr), G2),
                Gt => new GObject(Interop.gt_add(p1.ptr, p2.ptr), Gt),
                _ => throw new Exception($"Bls12381 operation fault,type:format,error:valid point length")
            };
        }

        public static GObject Mul(GObject p, ulong x)
        {
            return p.type switch
            {
                G1 => new GObject(Interop.g1_mul(p.ptr, x), G1),
                G2 => new GObject(Interop.g2_mul(p.ptr, x), G2),
                Gt => new GObject(Interop.gt_mul(p.ptr, x), Gt),
                _ => throw new Exception($"Bls12381 operation falut,type:format,error:valid point length")
            };
        }

        public static GObject Pairing(GObject p1, GObject p2)
        {
            if (p1.type != G1 || p2.type != G2)
            {
                throw new Exception($"Bls12381 operation fault, type:format, error:type mismatch");
            }
            GObject gt = new(Interop.g1_g2_pairing(p1.ptr, p2.ptr), Gt);
            return gt;
        }

        public byte[] ToByteArray()
        {
            byte[] buffer = GC.AllocateUninitializedArray<byte>(type);
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
            return buffer;
        }
    }
}
