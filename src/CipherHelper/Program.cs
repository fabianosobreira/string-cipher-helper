using System;
using System.Diagnostics;
using System.Linq;
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

            using (var hashHelper = new StringHashHelper<MD5CryptoServiceProvider>())
            {
                TestHashAlgorithm(hashHelper, textToTest, interactions);
            }

            using (var hashHelper = new StringHashHelper<SHA1CryptoServiceProvider>())
            {
                TestHashAlgorithm(hashHelper, textToTest, interactions);
            }

            using (var hashHelper = new StringHashHelper<SHA256CryptoServiceProvider>())
            {
                TestHashAlgorithm(hashHelper, textToTest, interactions);
            }

            using (var hashHelper = new StringHashHelper<SHA384CryptoServiceProvider>())
            {
                TestHashAlgorithm(hashHelper, textToTest, interactions);
            }

            using (var hashHelper = new StringHashHelper<SHA512CryptoServiceProvider>())
            {
                TestHashAlgorithm(hashHelper, textToTest, interactions);
            }

            Console.WriteLine("Testing Symmetric algorithms...");

            using(var cipherHelper = new StringCipherHelper<RC2CryptoServiceProvider>())
            {
                TestSymmetricAlgorithm(cipherHelper, textToTest, passPhrase, interactions);
            }

            using(var cipherHelper = new StringCipherHelper<DESCryptoServiceProvider>())
            {
                TestSymmetricAlgorithm(cipherHelper, textToTest, passPhrase, interactions);
            }

            using(var cipherHelper = new StringCipherHelper<TripleDESCryptoServiceProvider>())
            {
                TestSymmetricAlgorithm(cipherHelper, textToTest, passPhrase, interactions);
            }

            using(var cipherHelper = new StringCipherHelper<AesCryptoServiceProvider>())
            {
                TestSymmetricAlgorithm(cipherHelper, textToTest, passPhrase, interactions);
            }

            Console.WriteLine("Test finished.");
        }

        private static void TestSymmetricAlgorithm<T>(IStringCipherHelper<T> helper, string textToCipher, string passPhrase, int interactions)
            where T : SymmetricAlgorithm
        {
            Stopwatch sw = Stopwatch.StartNew();

            for (int i = 0; i < interactions; i++)
            {
                string helloEncrypted = helper.Encrypt(textToCipher, passPhrase);
                string helloDecrypted = helper.Decrypt(helloEncrypted, passPhrase);

                Debug.Assert(textToCipher != helloEncrypted);
                Debug.Assert(textToCipher == helloDecrypted);
            }

            sw.Stop();

            string algorithm = helper.GetType().GetGenericArguments().First().Name;

            Console.WriteLine($"Ellapsed after {interactions} interactions using {algorithm}: {sw.Elapsed}");
        }

        private static void TestHashAlgorithm<T>(IStringHashHelper<T> helper, string textToHash, int interactions)
            where T : HashAlgorithm
        {
            Stopwatch sw = Stopwatch.StartNew();

            for (int i = 0; i < interactions; i++)
            {
                string hash = helper.Hash(textToHash);
                Debug.Assert(helper.HashIsValid(textToHash, hash));
            }

            sw.Stop();

            string algorithm = helper.GetType().GetGenericArguments().First().Name;

            Console.WriteLine($"Ellapsed after {interactions} interactions using {algorithm}: {sw.Elapsed}");
        }
    }
}
