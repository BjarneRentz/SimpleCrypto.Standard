using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SimpleCrypto.Tests
{
    /// <summary>
    /// Custom Attribute to verify the given Exception and its message.
    /// </summary>
    public class ExpectedExceptionMessage : ExpectedExceptionBaseAttribute
    {
        private readonly Type expectedExceptionType;
        private readonly string expectedExceptionMessage;

        public ExpectedExceptionMessage(Type expectedExceptionType)
        {
            this.expectedExceptionType = expectedExceptionType;
            this.expectedExceptionMessage = string.Empty;
        }

        public ExpectedExceptionMessage(Type expectedExceptionType, string expectedExceptionMessage)
        {
            this.expectedExceptionType = expectedExceptionType;
            this.expectedExceptionMessage = expectedExceptionMessage;
        }
        
        protected override void Verify(Exception exception)
        {
            Assert.IsNotNull(exception);
            Assert.IsInstanceOfType(exception, expectedExceptionType, $"Expected Type {expectedExceptionType}, got {exception.GetType()}");

            if (!string.IsNullOrEmpty(expectedExceptionMessage))
            {
                Assert.AreEqual(expectedExceptionMessage, exception.Message, $"Expected Exception message: {expectedExceptionMessage}, got ${exception.Message}");
            }
        }
    }
}