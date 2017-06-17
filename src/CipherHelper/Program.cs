using System;
using System.Diagnostics;

namespace CipherHelper
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            const string textToCipher = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
            const string passPhrase = "my-secret-key";
            const int interactions = 100;

            Run(new TripleDesCipherHelper(), textToCipher, passPhrase, interactions);
            Run(new RijndaelCipherHelper(), textToCipher, passPhrase, interactions);
        }

        private static void Run(ICipherHelper helper, string textToCipher, string passPhrase, int interactions)
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

            Console.WriteLine($"Ellapsed after {interactions} using {helper.GetType().Name}: {sw.Elapsed}");
        }
    }
}
