using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace prviKlijent
{

    public class LEA
    {
        public static int Nr = 32;




        public static string LEAEncryptionCTR(byte[] key, byte[] iv, string plainText)
        {
            plainText = plainText.Replace(Environment.NewLine, string.Empty);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = new byte[plainBytes.Length];

            for (int blockOffset = 0; blockOffset < plainBytes.Length; blockOffset += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(plainBytes, blockOffset, block, 0, Math.Min(16, plainBytes.Length - blockOffset));

                byte[] cipherBlock = LEAEncryptBlock(key, iv);
                for (int i = 0; i < Math.Min(16, plainBytes.Length - blockOffset); i++)
                {
                    encryptedBytes[blockOffset + i] = (byte)(block[i] ^ cipherBlock[i]);
                }
            }


            return Convert.ToBase64String(encryptedBytes);
        }

        public static string LEADecryptionCTR(byte[] key, byte[] iv, string base64CipherText)
        {
            string decryptedResult = null;
            try
            {
                byte[] cipherTextBytes = Convert.FromBase64String(base64CipherText);

                byte[] decryptedBytes = new byte[cipherTextBytes.Length];

                for (int blockOffset = 0; blockOffset < cipherTextBytes.Length; blockOffset += 16)
                {
                    byte[] block = new byte[16];
                    Array.Copy(cipherTextBytes, blockOffset, block, 0, Math.Min(16, cipherTextBytes.Length - blockOffset));


                    byte[] decryptedBlock = LEAEncryptBlock(key, iv);
                    for (int i = 0; i < Math.Min(16, cipherTextBytes.Length - blockOffset); i++)
                    {
                        decryptedBytes[blockOffset + i] = (byte)(block[i] ^ decryptedBlock[i]);
                    }
                }

                decryptedResult = Encoding.UTF8.GetString(decryptedBytes);


            }
            catch (FormatException ex)
            {
                Console.WriteLine($"Greska kod BASE64: {ex.Message}");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greska prilikom LEA dekripcije: {ex.Message}");

            }

            return decryptedResult;
        }


        public static byte[] LEAEncryptBlock(byte[] key, byte[] iv)
        {
            byte[] state = new byte[16];
            byte[] roundKey;

            Array.Copy(iv, state, 16);


            AddRoundKey(ref state, key);


            for (int round = 0; round < Nr; round++)
            {
                roundKey = GenerateRoundKey(key, round);
                SubstitutionPermutation(ref state, roundKey);
            }


            AddRoundKey(ref state, key);

            return state;
        }

        static void SubstitutionPermutation(ref byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < state.Length; i++)
            {
                state[i] ^= roundKey[i];
            }
        }

        static void AddRoundKey(ref byte[] state, byte[] roundKey)
        {

            for (int i = 0; i < state.Length; i++)
            {
                state[i] ^= roundKey[i];
            }
        }

        static byte[] GenerateRoundKey(byte[] key, int round)
        {

            byte[] roundKey = new byte[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                roundKey[i] = (byte)(key[i] ^ 0x55);
            }
            return roundKey;
        }

        static int GetKeySizeInBits()
        {
            return 256;
        }

        static int GetBlockSizeInBits()
        {
            return 128;
        }

        public static byte[] GenerateRandomKey()
        {

            string keyString = ConfigurationManager.AppSettings["LEA"];
            byte[] key = Encoding.UTF8.GetBytes(keyString);

            byte[] delta = Encoding.UTF8.GetBytes("abcdefgh");

            byte[] t = new byte[8];

            for (int i = 0; i < 32; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    t[j] = key[j];
                }

                for (int j = 0; j < 6; j++)
                {
                    int idx = 6 * i + j;
                    int mod8 = idx % 8;
                    int modDelta = i % 8;

                    t[mod8] = (byte)((t[mod8] + (byte)(delta[modDelta] << (idx + 1))) << 1);

                    int mod6 = j * 4 % 6;
                    key[j] = (byte)(t[mod8] >> mod6);
                }
            }

            return key;
        }

        public static byte[] GenerateRandomIV()
        {
            string ivString = ConfigurationManager.AppSettings["IV"];
            byte[] iv = Encoding.UTF8.GetBytes(ivString);
            return iv;
        }
    }


}
