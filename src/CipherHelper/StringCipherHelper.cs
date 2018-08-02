using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CipherHelper
{
    public class StringCipherHelper<T> : IStringCipherHelper<T>
        where T : SymmetricAlgorithm, new()
    {
        private readonly SymmetricAlgorithm algorithm;
        private readonly int keySizeInBytes;
        private readonly int blockSizeInBytes;

        public StringCipherHelper()
        {
            algorithm = new T();
            keySizeInBytes = algorithm.KeySize / 8;
            blockSizeInBytes = algorithm.BlockSize / 8;
        }

        public void Dispose()
        {
            algorithm.Dispose();
        }

        public string Encrypt(string plainText, string passPhrase)
        {
            algorithm.GenerateIV();
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, algorithm.IV))
            {
                byte[] key = password.GetBytes(keySizeInBytes);

                using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, algorithm.IV))
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();

                    IEnumerable<byte> cipherTextBytes = algorithm.IV;
                    cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray());

                    return Convert.ToBase64String(cipherTextBytes.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText, string passPhrase)
        {
            byte[] cipherTextBytesWithIV = Convert.FromBase64String(cipherText);

            byte[] intializationVector = cipherTextBytesWithIV
                .Take(blockSizeInBytes)
                .ToArray();

            byte[] cipherTextBytes = cipherTextBytesWithIV
                .Skip(blockSizeInBytes)
                .Take(cipherTextBytesWithIV.Length - blockSizeInBytes)
                .ToArray();

            using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, algorithm.IV))
            {
                byte[] key = password.GetBytes(keySizeInBytes);

                using (ICryptoTransform decryptor = algorithm.CreateDecryptor(key, intializationVector))
                using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    byte[] plainTextBytes = new byte[cipherTextBytes.Length];
                    int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

                    return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                }
            }
        }
    }
}
