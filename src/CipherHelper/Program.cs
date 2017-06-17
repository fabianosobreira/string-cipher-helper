using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace CipherHelper
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            const string textToCipher = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
            const string passPhrase = "my-secret-key";
            const int interactions = 100;

            using (RC2 rc2 = RC2.Create())
            {
                Run(rc2, textToCipher, passPhrase, interactions);
            }

            using (TripleDES tdes = TripleDES.Create())
            {
                Run(tdes, textToCipher, passPhrase, interactions);
            }

            using (Rijndael rijndael = Rijndael.Create())
            {
                Run(rijndael, textToCipher, passPhrase, interactions);
            }
        }

        private static void Run(SymmetricAlgorithm algorithm, string textToCipher, string passPhrase, int interactions)
        {
            Stopwatch sw = Stopwatch.StartNew();
            ICipherHelper helper = new CipherHelper(algorithm);

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
    }
}
