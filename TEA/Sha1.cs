using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace prviKlijent
{
     public class Sha1
     {
         // SHA-1 functions
         public static string ComputeSHA1(byte[] fileBytes)
         {
             uint[] hash = InitializeSHA1();

             int bufferSize = 64; 
             uint[] words = new uint[80];

             int blockCount = fileBytes.Length / bufferSize;

             for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
             {
                 byte[] block = new byte[bufferSize];
                 Array.Copy(fileBytes, blockIndex * bufferSize, block, 0, bufferSize);

                 for (int i = 0; i < 16; i++)
                 {
                     words[i] = BitConverter.ToUInt32(block, i * 4);
                 }

                 for (int i = 16; i < 80; i++)
                 {
                     words[i] = CircularLeftShift(1, words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]);
                 }

                 hash = ProcessBlock(words, hash);
             }

             return GetHashString(hash);
         }

         static uint[] InitializeSHA1()
         {
             uint[] hash = new uint[5];
             hash[0] = 0x67452301;
             hash[1] = 0xEFCDAB89;
             hash[2] = 0x98BADCFE;
             hash[3] = 0x10325476;
             hash[4] = 0xC3D2E1F0;
             return hash;
         }

         static uint[] ProcessBlock(uint[] words, uint[] hash)
         {
             uint a = hash[0];
             uint b = hash[1];
             uint c = hash[2];
             uint d = hash[3];
             uint e = hash[4];

             for (int i = 0; i < 80; i++)
             {
                 uint f, k;

                 if (i < 20)
                 {
                     f = (b & c) | ((~b) & d);
                     k = 0x5A827999;
                 }
                 else if (i < 40)
                 {
                     f = b ^ c ^ d;
                     k = 0x6ED9EBA1;
                 }
                 else if (i < 60)
                 {
                     f = (b & c) | (b & d) | (c & d);
                     k = 0x8F1BBCDC;
                 }
                 else
                 {
                     f = b ^ c ^ d;
                     k = 0xCA62C1D6;
                 }

                 uint temp = CircularLeftShift(5, a) + f + e + k + words[i];
                 e = d;
                 d = c;
                 c = CircularLeftShift(30, b);
                 b = a;
                 a = temp;
             }

             hash[0] += a;
             hash[1] += b;
             hash[2] += c;
             hash[3] += d;
             hash[4] += e;

             return hash;
         }

         static uint CircularLeftShift(int bits, uint value)
         {
             return (value << bits) | (value >> (32 - bits));
         }

         static string GetHashString(uint[] hash)
         {
             StringBuilder result = new StringBuilder(40);

             for (int i = 0; i < 5; i++)
             {
                 result.Append(hash[i].ToString("X8"));
             }

             return result.ToString().ToLower();
         }

     }
}