using System;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleCrypto.Standard;

namespace SimpleCrypto.Tests
{
    [TestClass]
    public class Pkbdf2Tests
    {
        #region [ Compute ]

        
        [TestMethod]
        public void Compute_Ok()
        {
            var pbkdf2 = new Pbkdf2 {PlainText = "Test", Salt = "100000.Random"};

            var result = pbkdf2.Compute();
            
            Assert.IsNotNull(result);
            Assert.IsNotNull(pbkdf2.Salt);
            Assert.IsNotNull(pbkdf2.PlainText);
            Assert.IsNotNull(pbkdf2.HashedText);
            
            Assert.AreEqual(result, pbkdf2.HashedText);
        }

        /// <summary>
        /// Ensures that a <see cref="InvalidOperationException"/> gets thrown when the Plaintext is empty or null
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void Compute_PlainTextIsEmpty()
        {
            var pbkdf2 = new Pbkdf2 {Salt = "100000.Random"};

            pbkdf2.Compute();
            
            Assert.Fail();
        }
        
        /// <summary>
        /// Ensures that Salt will be generated if not set.
        /// </summary>
        [TestMethod]
        public void Compute_SaltIsEmpty()
        {
            var pbkdf2 = new Pbkdf2 {PlainText = "Test"};

            var result = pbkdf2.Compute();
            
            Assert.IsNotNull(result);
            Assert.IsNotNull(pbkdf2.Salt);
            Assert.IsNotNull(pbkdf2.PlainText);
            Assert.IsNotNull(pbkdf2.HashedText);
            
            Assert.AreEqual(result, pbkdf2.HashedText);
        }
        /// <summary>
        /// Ensures a <see cref="FormatException"/> gets thrown when the format of the given salt is invalid.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void Compute_ExtractSaltException()
        {
            var pbkdf2 = new Pbkdf2 {PlainText = "Test", Salt = "100A00.Random"};

            pbkdf2.Compute();
            
            Assert.Fail();
        }
        

        #endregion
        
        #region [GenerateSalt]
        
        [TestMethod]
        public void GenerateSalt_Ok()
        {
            var pbkdf2 = new Pbkdf2 {PlainText = "Test", Salt = "100A00.Random"};

            var salt = pbkdf2.GenerateSalt();

            Assert.AreEqual(pbkdf2.Salt, salt);
            Assert.IsTrue(new Regex($@"^{pbkdf2.HashIterations}\..+$").IsMatch(salt));
        }

        /// <summary>
        /// Ensures a <see cref="InvalidOperationException"/> gets thrown when the salt size is less than 1.
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void GenerateSalt_SaltSizeIsLessThanOne()
        {
            var pbkdf2 = new Pbkdf2 {PlainText = "Test", SaltSize = 0};

            pbkdf2.GenerateSalt();

            Assert.Fail();
        }

        /// <summary>
        /// Ensures <see cref="IPbkdf2.HashInterations"/> and <<see cref="IPbkdf2.SaltSize"/> are set with arguments.
        /// </summary>
        [TestMethod]
        public void GenerateSalt_OkWithArguments()
        {
            var pbkdf2 = new Pbkdf2 {PlainText = "Test"};

            var salt = pbkdf2.GenerateSalt(42, 16);
            
            Assert.AreEqual(42, pbkdf2.HashIterations);
            Assert.AreEqual(16, pbkdf2.SaltSize);
            Assert.AreEqual(pbkdf2.Salt, salt);
            Assert.IsTrue(new Regex(@"^42\.").IsMatch(salt));
        }
        
        #endregion
    }
}