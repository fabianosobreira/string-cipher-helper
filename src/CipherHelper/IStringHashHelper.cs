namespace CipherHelper
{
    interface IStringHashHelper
    {
        string Hash(string text);
        bool HashIsValid(string text, string hash);
    }
}
