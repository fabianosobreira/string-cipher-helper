using System;
using System.Security.Cryptography;
using System.Text;

namespace CipherHelper
{
    class StringHashHelper<T> : IStringHashHelper<T>
        where T : HashAlgorithm, new()
    {
        private HashAlgorithm algorithm;

        public StringHashHelper()
        {
            algorithm = new T();
        }

        public void Dispose()
        {
            algorithm.Dispose();
        }

        public string Hash(string text)
        {
            if (text == null)
            {
                throw new ArgumentNullException(nameof(text));
            }

            byte[] computedHash = algorithm.ComputeHash(Encoding.Default.GetBytes(text));

            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < computedHash.Length; i++)
            {
                builder.Append(computedHash[i].ToString("x2"));
            }

            return builder.ToString();
        }

        public bool HashIsValid(string text, string hash)
        {
            if (text == null)
            {
                throw new ArgumentNullException(nameof(text));
            }

            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            string hashOfText = Hash(text);

            return hashOfText.Equals(hash, StringComparison.OrdinalIgnoreCase);
        }
    }
}
