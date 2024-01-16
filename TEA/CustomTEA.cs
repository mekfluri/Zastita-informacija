using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace prviKlijent
{

    public class CustomTEA
    {

        private void TransformData(uint[] data, uint[] key)
        {
            uint a = data[0];
            uint b = data[1];
            uint sum = 0;
            uint delta = 0x9e3779b9;
            uint rounds = 32;

            while (rounds-- > 0)
            {
                a += (b << 4 ^ b >> 5) + b ^ sum + key[sum & 3];
                sum += delta;
                b += (a << 4 ^ a >> 5) + a ^ sum + key[sum >> 11 & 3];
            }

            data[0] = a;
            data[1] = b;
        }

        private string UIntToEncodedString(uint input)
        {
            return $"{(char)(input & 0xFF)}{(char)((input >> 8) & 0xFF)}{(char)((input >> 16) & 0xFF)}{(char)((input >> 24) & 0xFF)}";
        }

        private uint EncodedStringToUInt(string input)
        {
            if (input.Length < 4)
            {
                input = input.PadRight(4, '\0');
            }

            uint output = ((uint)input[0]);
            output += ((uint)input[1] << 8);
            output += ((uint)input[2] << 16);
            output += ((uint)input[3] << 24);
            return output;
        }

        private uint[] FormatEncryptionKey(string key)
        {
            key = key.PadRight(16, '\0');

            uint[] formattedKey = new uint[4];
            for (int i = 0; i < 4; i++)
            {
                formattedKey[i] = EncodedStringToUInt(key.Substring(i * 4, 4));
            }

            return formattedKey;
        }

        public string EncryptData(string input, string encryptionKey)
        {
            uint[] formattedKey = FormatEncryptionKey(encryptionKey);

            if (input.Length % 2 != 0)
            {
                input += '\0';
            }

            byte[] inputBytes = Encoding.ASCII.GetBytes(input);

            StringBuilder encryptedResult = new StringBuilder();
            uint[] tempData = new uint[2];

            for (int i = 0; i < inputBytes.Length; i += 2)
            {
                tempData[0] = inputBytes[i];
                tempData[1] = inputBytes[i + 1];
                TransformData(tempData, formattedKey);
                encryptedResult.Append(UIntToEncodedString(tempData[0]) + UIntToEncodedString(tempData[1]));
            }

            return encryptedResult.ToString();
        }

        private void ReverseTransformData(uint[] data, uint[] key)
        {
            uint rounds = 32;
            uint sum;
            uint a = data[0];
            uint b = data[1];
            uint delta = 0x9e3779b9;

            sum = delta << 5;

            while (rounds-- > 0)
            {
                b -= (a << 4 ^ a >> 5) + a ^ sum + key[sum >> 11 & 3];
                sum -= delta;
                a -= (b << 4 ^ b >> 5) + b ^ sum + key[sum & 3];
            }

            data[0] = a;
            data[1] = b;
        }

        public string DecryptData(string input, string decryptionKey)
        {
            uint[] formattedKey = FormatEncryptionKey(decryptionKey);

            int index = 0;
            uint[] tempData = new uint[2];
            byte[] inputBytes = new byte[input.Length / 8 * 2];

            for (int i = 0; i < input.Length; i += 8)
            {
                if (i + 8 <= input.Length)
                {
                    tempData[0] = EncodedStringToUInt(input.Substring(i, 4));
                    tempData[1] = EncodedStringToUInt(input.Substring(i + 4, 4));
                    ReverseTransformData(tempData, formattedKey);
                    inputBytes[index++] = (byte)tempData[0];
                    inputBytes[index++] = (byte)tempData[1];
                }
                else
                {
                    break;
                }
            }

            string decryptedResult = Encoding.ASCII.GetString(inputBytes, 0, index);

            if (decryptedResult.Length > 0 && decryptedResult[decryptedResult.Length - 1] == '\0')
            {
                decryptedResult = decryptedResult.Substring(0, decryptedResult.Length - 1);
            }

            return decryptedResult;
        }
    }
}
