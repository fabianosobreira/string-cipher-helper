using System.Security.Cryptography;

namespace CipherHelper
{
    interface IStringHashHelper<T>
        where T : HashAlgorithm
    {
        string Hash(string text);
        bool HashIsValid(string text, string hash);
    }
}
