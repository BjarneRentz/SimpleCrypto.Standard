using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
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
            this.SaltSize = 16;
            this.HashIterations = 400000;
        }

        
        public int HashIterations { get; set; }
        public int SaltSize { get; set; }
        public string PlainText { get; set; }
        public string HashedText { get; private set; }
        public string Salt { get; set; }
        
        public string Compute()
        {
            if(String.IsNullOrEmpty(PlainText))
                throw new InvalidOperationException("Plaintext can´t be empty.");
            if (String.IsNullOrEmpty(Salt))
                GenerateSalt();
            
            ExtractHashIteration();
            
            byte[] saltBytes = Encoding.UTF8.GetBytes(Salt);

            var pbkdf2 = new Rfc2898DeriveBytes(PlainText, saltBytes, HashIterations);
            var key = pbkdf2.GetBytes(64);
            
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
            var rng = RandomNumberGenerator.Create();

            var randomBytes = new Byte[SaltSize];
            
            rng.GetBytes(randomBytes);

            Salt = $"{HashIterations}.{Convert.ToBase64String(randomBytes)}";
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

        public bool Compare(string passwordHash1, string passwordHash2)
        {
            if (string.IsNullOrEmpty(passwordHash1) || string.IsNullOrEmpty(passwordHash2))
                return false;

            if (passwordHash1.Length != passwordHash2.Length)
                return false;

            int minLength = Math.Min(passwordHash1.Length, passwordHash2.Length);
            int result = 0;

            for (int i = 0; i < minLength; i++)
                result |= passwordHash1[i] ^ passwordHash2[i];

            return 0 == result;
        }
        /// <summary>
        /// Extracts the hash iterations from the salt.
        /// </summary>
        /// <exception cref="FormatException">Salt has not the format {int}.{string}</exception>
        private void ExtractHashIteration()
        {
            try
            {
                //get the position of the . that splits the string
                var i = Salt.IndexOf('.');

                //Get the hash iteration from the first index
                HashIterations = int.Parse(Salt.Substring(0, i), System.Globalization.NumberStyles.Number);

            }
            catch (Exception)
            {
                throw new FormatException("The salt was not in an expected format of {int}.{string}");
            }
        }
    }
}