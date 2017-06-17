using System;
using System.Security.Cryptography;
using System.Text;

namespace CipherHelper
{
    /**
     * Symmetric string cipher implementation using TripleDES
     */
    public class TripleDesCipherHelper : ICipherHelper
    {
        public string Encrypt(string plainText, string passPhrase)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(plainText);

            using (var md5 = MD5.Create())
            {
                keyArray = md5.ComputeHash(Encoding.UTF8.GetBytes(passPhrase));
            }

            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                using (var encryptor = tdes.CreateEncryptor())
                {
                    byte[] resultArray = encryptor.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                    return Convert.ToBase64String(resultArray, 0, resultArray.Length);
                }
            }
        }

        public string Decrypt(string cipherText, string passPhrase)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Convert.FromBase64String(cipherText);

            using (var md5 = MD5.Create())
            {
                keyArray = md5.ComputeHash(Encoding.UTF8.GetBytes(passPhrase));
            }

            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                using (var cTransform = tdes.CreateDecryptor())
                {
                    byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                    return UTF8Encoding.UTF8.GetString(resultArray);
                }
            }
        }
    }
}
