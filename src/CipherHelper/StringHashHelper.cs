using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CipherHelper
{
    class StringHashHelper<T> : IStringHashHelper<T>
        where T : HashAlgorithm, new()
    {
        private const int saltSizeInBytes = 8;

        public string Hash(string text)
        {
            if (string.IsNullOrEmpty(text)) throw new ArgumentNullException(nameof(text));
            return Hash(text, GenerateEntropy());
        }

        public bool HashIsValid(string text, string hash)
        {
            if (string.IsNullOrEmpty(text)) throw new ArgumentNullException(nameof(text));
            if (string.IsNullOrEmpty(hash)) throw new ArgumentNullException(nameof(hash));

            byte[] saltBytes = ExtractSalt(hash);
            string hashOfText = Hash(text, saltBytes);
            return hashOfText.Equals(hash, StringComparison.OrdinalIgnoreCase);
        }

        private static byte[] ExtractSalt(string hash)
        {
            List<byte> salt = new List<byte>(saltSizeInBytes);

            for (int i = 0; i < saltSizeInBytes * 2; i++)
            {
                if (i % 2 == 0)
                {
                    salt.Add(Convert.ToByte(hash.Substring(i, 2), 16));
                }
            }

            return salt.ToArray();
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

        private string Hash(string text, byte[] salt)
        {
            using (HashAlgorithm algorithm = new T())
            {
                byte[] computedHash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(text));
                IEnumerable<byte> computedHashWithSalt = salt.Concat(computedHash);
                StringBuilder builder = new StringBuilder((computedHash.Length + saltSizeInBytes) * 2);

                foreach (byte value in computedHashWithSalt)
                {
                    builder.Append(value.ToString("x2"));
                }

                return builder.ToString();
            }
        }
    }
}
