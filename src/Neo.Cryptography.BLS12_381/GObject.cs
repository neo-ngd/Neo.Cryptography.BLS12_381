using System;
using System.Runtime.InteropServices;

namespace Neo.Cryptography.BLS12_381
{
    /// <summary>
    /// Meta data
    /// </summary>
    public class GObject
    {
        public IntPtr ptr;
        public GType type;

        public GObject(GType t, IntPtr ptr)
        {
            this.ptr = ptr;
            this.type = t;
        }

        public GObject(byte[] g)
        {
            int len = g.Length;
            if (len is (int)GType.G1 or (int)GType.G2 or (int)GType.Gt)
            {
                IntPtr tmp = Marshal.AllocHGlobal(len);
                Marshal.Copy(g, 0, tmp, len);
                this.type = (GType)len;
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
                    case GType.G1:
                        Interop.g1_dispose(ptr);
                        break;
                    case GType.G2:
                        Interop.g2_dispose(ptr);
                        break;
                    case GType.Gt:
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
                GType.G1 => new GObject(GType.G1, Interop.g1_neg(ptr)),
                GType.G2 => new GObject(GType.G2, Interop.g2_neg(ptr)),
                GType.Gt => new GObject(GType.Gt, Interop.gt_neg(ptr)),
                _ => throw new Exception($"Bls12381 operation fault, type:format, error:valid point length")
            };
            return G;
        }
    }
}
