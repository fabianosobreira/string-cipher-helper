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
            const int iterations = 1000;

            Console.WriteLine("Testing Hash algorithms...");

            var md5 = new StringHashHelper<MD5CryptoServiceProvider>();
            TestHashAlgorithm(md5, textToTest, iterations);

            var sha1 = new StringHashHelper<SHA1CryptoServiceProvider>();
            TestHashAlgorithm(sha1, textToTest, iterations);

            var sha256 = new StringHashHelper<SHA256CryptoServiceProvider>();
            TestHashAlgorithm(sha256, textToTest, iterations);

            var sha384 = new StringHashHelper<SHA384CryptoServiceProvider>();
            TestHashAlgorithm(sha384, textToTest, iterations);

            var sha512 = new StringHashHelper<SHA512CryptoServiceProvider>();
            TestHashAlgorithm(sha512, textToTest, iterations);

            Console.WriteLine("Testing Symmetric algorithms...");

            var rc2 = new StringCipherHelper<RC2CryptoServiceProvider>();
            TestSymmetricAlgorithm(rc2, textToTest, passPhrase, iterations);

            var des = new StringCipherHelper<DESCryptoServiceProvider>();
            TestSymmetricAlgorithm(des, textToTest, passPhrase, iterations);

            var tdes = new StringCipherHelper<TripleDESCryptoServiceProvider>();
            TestSymmetricAlgorithm(tdes, textToTest, passPhrase, iterations);

            var aes = new StringCipherHelper<AesCryptoServiceProvider>();
            TestSymmetricAlgorithm(aes, textToTest, passPhrase, iterations);

            Console.WriteLine("Test finished.");
            Console.ReadKey();
        }

        private static void TestSymmetricAlgorithm<T>(IStringCipherHelper<T> helper, string textToCipher, string passPhrase, int iterations)
            where T : SymmetricAlgorithm
        {
            Stopwatch sw = Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                string helloEncrypted = helper.Encrypt(textToCipher, passPhrase);
                string helloDecrypted = helper.Decrypt(helloEncrypted, passPhrase);

                Debug.Assert(textToCipher != helloEncrypted);
                Debug.Assert(textToCipher == helloDecrypted);
            }

            sw.Stop();

            string algorithm = helper.GetType().GetGenericArguments().First().Name;

            Console.WriteLine($"Ellapsed after {iterations} iterations using {algorithm}: {sw.Elapsed}");
        }

        private static void TestHashAlgorithm<T>(IStringHashHelper<T> helper, string textToHash, int iterations)
            where T : HashAlgorithm
        {
            Stopwatch sw = Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                string hash = helper.Hash(textToHash);
                Debug.Assert(helper.HashIsValid(textToHash, hash));
            }

            sw.Stop();

            string algorithm = helper.GetType().GetGenericArguments().First().Name;

            Console.WriteLine($"Ellapsed after {iterations} iterations using {algorithm}: {sw.Elapsed}");
        }
    }
}
