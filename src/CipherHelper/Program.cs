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

            using (Aes algorithm = Aes.Create())
            {
                Run(algorithm, textToCipher, passPhrase, interactions);
            }

            using (DES algorithm = DES.Create())
            {
                Run(algorithm, textToCipher, passPhrase, interactions);
            }

            using (RC2 algorithm = RC2.Create())
            {
                Run(algorithm, textToCipher, passPhrase, interactions);
            }

            using (Rijndael algorithm = Rijndael.Create())
            {
                Run(algorithm, textToCipher, passPhrase, interactions);
            }

            using (TripleDES algorithm = TripleDES.Create())
            {
                Run(algorithm, textToCipher, passPhrase, interactions);
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
