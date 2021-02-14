using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using SimpleCrypto.Standard.Exceptions;
using SimpleCrypto.Standard.Interfaces;

namespace SimpleCrypto.Standard
{
    /// <summary>
    /// Implementation of <see cref="IPbkdf2"/>
    /// </summary>
    public class Pbkdf2 : IPbkdf2
    {
        public Pbkdf2()
        {
            this.SaltSize = 64;
            this.HashIterations = 100000;
            this.HashSize = 64;
            this.HashAlgorithm = HashAlgorithmName.SHA512;
        }

        
        public int HashIterations { get; set; }
        
        public HashAlgorithmName HashAlgorithm { get; set; }
        public int SaltSize { get; set; }
        public string PlainText { get; set; }
        public string HashedText { get; private set; }
        public string Salt { get; set; }
        public int HashSize { get; set;  }
        
        public string Compute()
        {
            CheckConditions();
            if(String.IsNullOrEmpty(PlainText))
                throw new InvalidOperationException("Plaintext can´t be empty.");
            if (String.IsNullOrEmpty(Salt))
                GenerateSalt();
            
            ExtractHashIterationAndHmac();
            
            byte[] saltBytes = Encoding.UTF8.GetBytes(Salt);

            var pbkdf2 = new Rfc2898DeriveBytes(PlainText, saltBytes, HashIterations);
            var key = pbkdf2.GetBytes(HashSize);
            
            HashedText = Convert.ToBase64String(key);

            return HashedText;
        }

        public string Compute(string textToHash)
        {
            PlainText = textToHash;

            return Compute();
        }

        public string Compute(string textToHash, string salt)
        {
            PlainText = textToHash;
            Salt = salt;
            return Compute();
        }

        public string Compute(string textToHash, int saltSize, int hashIterations)
        {
            PlainText = textToHash;
            SaltSize = saltSize;
            HashIterations = hashIterations;
            return Compute();
        }

        public string GenerateSalt()
        {
            if (SaltSize<1)
                throw new InvalidOperationException("Salt has to greater than 1!");
            
            var randomBytes = new Byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            
            Salt = $"{HashAlgorithm.Name}.{HashIterations}.{Convert.ToBase64String(randomBytes)}";
            return Salt;
        }

        public string GenerateSalt(int hashIterations, int saltSize)
        {
            HashIterations = hashIterations;
            SaltSize = saltSize;
            return GenerateSalt();
        }

        public int GetElapsedTimeForIteration(int iteration)
        {
            var stopWatch = new Stopwatch();
            HashIterations = iteration;
            stopWatch.Start();

            Compute();
            
            stopWatch.Stop();

            return (int)stopWatch.ElapsedMilliseconds;

        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        public bool Compare(string passwordHash1, string passwordHash2)
        {
            if (passwordHash1?.Length != passwordHash2?.Length)
                return false;

            int result = 0;

            for (int i = 0; i < (passwordHash1?.Length ?? 0); i++)
                result |= passwordHash1[i] ^ passwordHash2[i];

            return 0 == result;
        }
        /// <summary>
        /// Extracts the hash iterations from the salt.
        /// </summary>
        /// <exception cref="FormatException">Salt has not the format {int}.{string}</exception>
        private void ExtractHashIterationAndHmac()
        {
            try
            {
                var content = Salt.Split('.');
                

                //Get the hash iteration from the first index
                HashIterations = int.Parse(content[1], System.Globalization.NumberStyles.Number);
                HashAlgorithm = new HashAlgorithmName(content[0]);

            }
            catch (Exception)
            {
                throw new FormatException("The salt was not in an expected format of {string}.{int}.{string}");
            }
        }


        /// <summary>
        /// Checks the conditions to throw a <see cref="InsecureOperationException"/>. 
        /// </summary>
        /// <exception cref="InsecureOperationException"></exception>
        /// <remarks>
        /// Salt size should be at least 8 Bytes, and the Hash size not greater than the output of the used HMAC.
        /// Hash size should not be smaller than the Salt size and the minimum hash iterations of 10 000 should not get undercutted.
        /// Also MD5 should never be used as the HMAC.
        /// </remarks>
        private void CheckConditions()
        {
            string message = null;

            if (HashAlgorithm.Equals(HashAlgorithmName.MD5))
                message = InsecureMessages.INSECURE_HMAC(HashAlgorithm.Name);
            if (SaltSize < 8)
                message = InsecureMessages.SALT_TO_SHORT;
            if (HashSize > GetHmacSize())
                message = InsecureMessages.HASH_SIZE_TO_BIG;
            if (HashSize < SaltSize)
                message = InsecureMessages.HASH_SIZE_TO_SMALL;
            if (HashIterations < 10000)
                message = InsecureMessages.NOT_ENOUGH_ITERATIONS;
            
            if (message !=null)
                throw new InsecureOperationException(message);
        }

        /// <summary>
        /// Returns the output size of the used <see cref="HashAlgorithm"/> in bytes.
        /// </summary>
        /// <returns></returns>
        private int GetHmacSize()
        {
            if (HashAlgorithm.Equals(HashAlgorithmName.SHA1))
                return 20;
            if (HashAlgorithm.Equals(HashAlgorithmName.SHA256))
                return 32;
            if (HashAlgorithm.Equals(HashAlgorithmName.SHA384))
                return 48;
            if (HashAlgorithm.Equals(HashAlgorithmName.SHA512))
                return 64;

            return 0;
        }
           

    }
}