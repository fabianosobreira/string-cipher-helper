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
        private const int iterations = 1000;

        public string Encrypt(string text, string pass)
        {
            if (string.IsNullOrEmpty(text)) throw new ArgumentNullException(nameof(text));
            if (string.IsNullOrEmpty(pass)) throw new ArgumentNullException(nameof(pass));

            using (SymmetricAlgorithm algorithm = new T())
            using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(pass, algorithm.IV, iterations))
            {
                int keySizeInBytes = algorithm.KeySize / 8;
                byte[] key = password.GetBytes(keySizeInBytes);

                using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, algorithm.IV))
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    byte[] value = Encoding.UTF8.GetBytes(text);
                    cryptoStream.Write(value, 0, value.Length);
                    cryptoStream.FlushFinalBlock();

                    IEnumerable<byte> cipherTextBytes = algorithm.IV;
                    cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray());

                    return Convert.ToBase64String(cipherTextBytes.ToArray());
                }
            }
        }

        public string Decrypt(string base64String, string pass)
        {
            if (string.IsNullOrEmpty(base64String)) throw new ArgumentNullException(nameof(base64String));
            if (string.IsNullOrEmpty(pass)) throw new ArgumentNullException(nameof(pass));

            using (SymmetricAlgorithm algorithm = new T())
            {
                int blockSizeInBytes = algorithm.BlockSize / 8;

                byte[] cipher = Convert.FromBase64String(base64String);
                byte[] iv = cipher.Take(blockSizeInBytes).ToArray();
                byte[] value = cipher.Skip(blockSizeInBytes).Take(cipher.Length - blockSizeInBytes).ToArray();

                using (Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(pass, iv, iterations))
                {
                    int keySizeInBytes = algorithm.KeySize / 8;
                    byte[] key = password.GetBytes(keySizeInBytes);

                    using (ICryptoTransform decryptor = algorithm.CreateDecryptor(key, iv))
                    using (MemoryStream memoryStream = new MemoryStream(value))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        byte[] plainTextBytes = new byte[value.Length];
                        int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                        return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                    }
                }
            }
        }
    }
}
