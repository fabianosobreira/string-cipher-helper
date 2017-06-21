using System;
using System.Security.Cryptography;

namespace CipherHelper
{
    interface IStringHashHelper<T> : IDisposable
        where T: HashAlgorithm
    {
        string Hash(string text);
        bool HashIsValid(string text, string hash);
    }
}
