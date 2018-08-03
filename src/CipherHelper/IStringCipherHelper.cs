using System.Security.Cryptography;

namespace CipherHelper
{
    public interface IStringCipherHelper<T>
        where T : SymmetricAlgorithm
    {
        string Encrypt(string text, string pass);
        string Decrypt(string base64String, string pass);
    }
}
