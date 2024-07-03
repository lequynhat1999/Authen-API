using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace AngularAuth.Common.Helpers
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int saltSize = 16;
        private static readonly int hashSize = 20;
        private static readonly int interations = 10000;
        

        /// <summary>
        /// Mã hóa password
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string HashPassword(string password)
        {
            byte[] salt;
            rng.GetBytes(salt = new byte[saltSize]);
            var key = new Rfc2898DeriveBytes(password, salt, interations);
            var hash = key.GetBytes(hashSize);

            var hashByte = new byte[saltSize + hashSize];
            Array.Copy(salt, 0, hashByte, 0, saltSize);
            Array.Copy(hash, 0, hashByte, saltSize, hashSize);

            var base64Hash = Convert.ToBase64String(hashByte);

            return base64Hash;
        }

        public static bool VerifyPassword(string password, string base64Hash)
        {
            var hashBytes = Convert.FromBase64String(base64Hash);

            var salt = new byte[saltSize];
            Array.Copy(hashBytes, 0, salt, 0, saltSize);

            var key = new Rfc2898DeriveBytes(password, salt, interations);
            byte[] hash = key.GetBytes(hashSize);

            for (var i = 0; i < hashSize; i++)
            {
                if (hashBytes[i + saltSize] != hash[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
