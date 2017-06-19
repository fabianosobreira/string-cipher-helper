using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CipherHelper
{
    public class StringCipherHelper : IStringCipherHelper
    {
        private readonly SymmetricAlgorithm algorithm;
        private readonly int keySizeInBytes;
        private readonly int blockSizeInBytes;
        private readonly int saltSizeInBytes;
        private readonly int derivationIterations = 1000;

        public StringCipherHelper(SymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            keySizeInBytes = algorithm.KeySize / 8;
            blockSizeInBytes = algorithm.BlockSize / 8;
            saltSizeInBytes = blockSizeInBytes * 2;
        }

        public StringCipherHelper(SymmetricAlgorithm algorithm, int derivationIterations)
            : this(algorithm)
        {
            this.derivationIterations = derivationIterations;
        }

        public string Encrypt(string plainText, string passPhrase)
        {
            byte[] salt = GenerateEntropy();
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, salt, derivationIterations))
            {
                byte[] key = password.GetBytes(keySizeInBytes);

                using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, algorithm.IV))
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();

                    IEnumerable<byte> cipherTextBytes = salt;
                    cipherTextBytes = cipherTextBytes.Concat(algorithm.IV);
                    cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray());

                    return Convert.ToBase64String(cipherTextBytes.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText, string passPhrase)
        {
            byte[] cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);

            byte[] salt = cipherTextBytesWithSaltAndIv.Take(saltSizeInBytes).ToArray();

            byte[] intializationVector = cipherTextBytesWithSaltAndIv
                .Skip(saltSizeInBytes)
                .Take(blockSizeInBytes)
                .ToArray();

            byte[] cipherTextBytes = cipherTextBytesWithSaltAndIv
                .Skip(saltSizeInBytes + blockSizeInBytes)
                .Take(cipherTextBytesWithSaltAndIv.Length - (saltSizeInBytes + blockSizeInBytes))
                .ToArray();

            using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, salt, derivationIterations))
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

        private byte[] GenerateEntropy()
        {
            byte[] randomBytes = new byte[saltSizeInBytes];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}
