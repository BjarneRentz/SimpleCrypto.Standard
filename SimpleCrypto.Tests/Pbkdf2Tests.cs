using System;
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

        [TestMethod]
        public void ComputeWithArgs_PlainText_Ok()
        {
            const string PLAIN_TEXT = "Test";
            
            var pbkdf2 = new Pbkdf2();

            var result = pbkdf2.Compute(PLAIN_TEXT);

            Assert.IsNotNull(result);
            Assert.AreEqual(PLAIN_TEXT, pbkdf2.PlainText);
            Assert.IsNotNull(pbkdf2.HashedText);

            Assert.AreEqual(result, pbkdf2.HashedText);
        }

        [TestMethod]
        public void ComputeWithArgs_PlainText_Salt_Ok()
        {
            const string PLAIN_TEXT = "Test";
            const string SALT = "100000.Random";

            var pbkdf2 = new Pbkdf2();

            var result = pbkdf2.Compute(PLAIN_TEXT, SALT);

            Assert.IsNotNull(result);
            Assert.AreEqual(PLAIN_TEXT, pbkdf2.PlainText);
            Assert.AreEqual(SALT, pbkdf2.Salt);
            Assert.IsNotNull(pbkdf2.HashedText);

            Assert.AreEqual(result, pbkdf2.HashedText);
        }

        [TestMethod]
        public void ComputeWithArgs_PlainText_SaltSize_Iterations_Ok()
        {
            const string PLAIN_TEXT = "Test";
            const int SALT_SIZE = 13;
            const int ITERATIONS = 123456;

            var pbkdf2 = new Pbkdf2();

            var result = pbkdf2.Compute(PLAIN_TEXT, SALT_SIZE, ITERATIONS);

            Assert.IsNotNull(result);
            Assert.AreEqual(PLAIN_TEXT, pbkdf2.PlainText);
            Assert.AreEqual(SALT_SIZE, pbkdf2.SaltSize);
            Assert.AreEqual(ITERATIONS, pbkdf2.HashIterations);
            Assert.IsNotNull(pbkdf2.HashedText);

            Assert.AreEqual(result, pbkdf2.HashedText);
        }

        #endregion
    }
}