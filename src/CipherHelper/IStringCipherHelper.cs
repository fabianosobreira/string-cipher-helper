using System;
using System.Security.Cryptography;

namespace CipherHelper
{
    public interface IStringCipherHelper<T>: IDisposable
        where T : SymmetricAlgorithm
    {
        string Encrypt(string plainText, string passPhrase);
        string Decrypt(string cipherText, string passPhrase);
    }
}
