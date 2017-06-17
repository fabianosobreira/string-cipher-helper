using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CipherHelper
{
    public class CipherHelper : ICipherHelper
    {
        private readonly SymmetricAlgorithm algorithm;
        private readonly int keySizeInBytes;
        private readonly int blockSizeInBytes;
        private readonly int saltSizeInBytes = 32;
        private readonly int derivationIterations = 1000;

        public CipherHelper(SymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            this.algorithm.Mode = CipherMode.CBC;
            this.algorithm.Padding = PaddingMode.PKCS7;

            keySizeInBytes = algorithm.KeySize / 8;
            blockSizeInBytes = algorithm.BlockSize / 8;
        }

        public CipherHelper(SymmetricAlgorithm algorithm, int derivationIterations)
            : this(algorithm)
        {
            this.derivationIterations = derivationIterations;
        }

        public string Encrypt(string plainText, string passPhrase)
        {
            byte[] salt = GenerateEntropy(saltSizeInBytes);
            byte[] intializationVector = GenerateEntropy(blockSizeInBytes);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, salt, derivationIterations))
            {
                byte[] key = password.GetBytes(keySizeInBytes);

                using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, intializationVector))
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();

                    IEnumerable<byte> cipherTextBytes = salt;
                    cipherTextBytes = cipherTextBytes.Concat(intializationVector);
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

        private byte[] GenerateEntropy(int sizeInBytes)
        {
            byte[] randomBytes = new byte[sizeInBytes];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}
