// Copyright (C) 2015-2022 The Neo Project.
// 
// The neo is free software distributed under the MIT software license, 
// see the accompanying file LICENSE in the main directory of the
// project or http://www.opensource.org/licenses/mit-license.php 
// for more details.
// 
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using System;

namespace Neo.Cryptography.BLS12_381
{
    /// <summary>
    /// A bls12_381 helper class 
    /// </summary>
    public static class Bls12381Wrapper
    {
        /// <summary>
        /// Add operation of two gt point
        /// </summary>
        /// <param name="p1Binary">Gt point1 as byteArray</param>
        /// <param name="p2Binary">Gt point2 as byteArray</param>
        /// <returns></returns>
        public static byte[] PointAdd(byte[] p1Binary, byte[] p2Binary)
        {
            GObject p1 = new GObject(p1Binary);
            GObject p2 = new GObject(p2Binary);
            try
            {
                return Interop.Add(p1, p2).ToByteArray((int)p1.type);
            }
            catch (Exception e)
            {
                throw new Exception($"Bls12381 operation fault, type:dll-add, error:{e}");
            }
        }

        /// <summary>
        /// Mul operation of gt point and mulitiplier
        /// </summary>
        /// <param name="pBinary">Gt point as byteArray</param>
        /// <param name="multi">Multiplier</param>
        /// <returns></returns>
        public static byte[] PointMul(byte[] pBinary, long multi)
        {
            try
            {
                GObject p = multi < 0 ? new GObject(pBinary).Neg() : new GObject(pBinary);
                var x = Convert.ToUInt64(Math.Abs(multi));
                return Interop.Mul(p, x).ToByteArray((int)p.type);
            }
            catch (Exception e)
            {
                throw new Exception($"Bls12381 operation fault, type:dll-mul, error:{e}");
            }
        }

        /// <summary>
        /// Pairing operation of g1 and g2
        /// </summary>
        /// <param name="g1Binary">Gt point1 as byteArray</param>
        /// <param name="g2Binary">Gt point2 as byteArray</param>
        /// <returns></returns>
        public static byte[] PointPairing(byte[] g1Binary, byte[] g2Binary)
        {
            try
            {
                return Interop.g1_g2_pairing(new GObject(g1Binary).ptr, new GObject(g2Binary).ptr).ToByteArray(576);
            }
            catch (Exception e)
            {
                throw new Exception($"Bls12381 operation fault, type:dll-pairing, error:{e}");
            }
        }
    }
}
