using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace CipherHelper
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            const string textToTest = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
            const string passPhrase = "my-secret-key";
            const int interactions = 100;

            Console.WriteLine("Testing Hash algorithms...");

            using (MD5 algorithm = new MD5CryptoServiceProvider())
            {
                TestHashAlgorithm(algorithm, textToTest, interactions);
            }

            using (SHA1 algorithm = new SHA1CryptoServiceProvider())
            {
                TestHashAlgorithm(algorithm, textToTest, interactions);
            }

            using (SHA256 algorithm = new SHA256CryptoServiceProvider())
            {
                TestHashAlgorithm(algorithm, textToTest, interactions);
            }

            using (SHA384 algorithm = new SHA384CryptoServiceProvider())
            {
                TestHashAlgorithm(algorithm, textToTest, interactions);
            }

            using (SHA512 algorithm = new SHA512CryptoServiceProvider())
            {
                TestHashAlgorithm(algorithm, textToTest, interactions);
            }

            Console.WriteLine("Testing Symmetric algorithms...");

            using (RC2 algorithm = new RC2CryptoServiceProvider())
            {
                TestSymmetricAlgorithm(algorithm, textToTest, passPhrase, interactions);
            }

            using (DES algorithm = new DESCryptoServiceProvider())
            {
                TestSymmetricAlgorithm(algorithm, textToTest, passPhrase, interactions);
            }

            using (TripleDES algorithm = new TripleDESCryptoServiceProvider())
            {
                TestSymmetricAlgorithm(algorithm, textToTest, passPhrase, interactions);
            }

            using (Aes algorithm = new AesCryptoServiceProvider())
            {
                TestSymmetricAlgorithm(algorithm, textToTest, passPhrase, interactions);
            }

            Console.WriteLine("Test finished.");
        }

        private static void TestSymmetricAlgorithm(SymmetricAlgorithm algorithm, string textToCipher, string passPhrase, int interactions)
        {
            Stopwatch sw = Stopwatch.StartNew();
            IStringCipherHelper helper = new StringCipherHelper(algorithm);

            for (int i = 0; i < interactions; i++)
            {
                string helloEncrypted = helper.Encrypt(textToCipher, passPhrase);
                string helloDecrypted = helper.Decrypt(helloEncrypted, passPhrase);

                Debug.Assert(textToCipher != helloEncrypted);
                Debug.Assert(textToCipher == helloDecrypted);
            }

            sw.Stop();

            Console.WriteLine($"Ellapsed after {interactions} interactions using {algorithm.GetType().Name}: {sw.Elapsed}");
        }

        private static void TestHashAlgorithm(HashAlgorithm algorithm, string textToHash, int interactions)
        {
            Stopwatch sw = Stopwatch.StartNew();
            IStringHashHelper helper = new StringHashHelper(algorithm);

            for (int i = 0; i < interactions; i++)
            {
                string hash = helper.Hash(textToHash);
                Debug.Assert(helper.HashIsValid(textToHash, hash));
            }

            sw.Stop();

            Console.WriteLine($"Ellapsed after {interactions} interactions using {algorithm.GetType().Name}: {sw.Elapsed}");
        }
    }
}
