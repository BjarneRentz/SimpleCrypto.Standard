using System;

namespace SimpleCrypto.Standard.Exceptions
{
    
    /// <summary>
    /// Represents an unsecure Configuration / Operation.
    /// </summary>
    /// <remarks>
    ///    Gets thrown when the Compute method gets called with insecure configurations. 
    /// </remarks>
    public class InsecureOperationException : Exception
    {
        /// <summary>
        /// Default Constructor of the Exception
        /// </summary>
        public InsecureOperationException() {}
        
        /// <summary>
        /// Creates an InsecureOperationException with a message.
        /// </summary>
        /// <param name="message">Exception message to provide further information.</param>
        public InsecureOperationException(string message) : base(message) {}
        
        /// <summary>
        /// Creates an InsecureOperationException with a message and inner exception.
        /// </summary>
        /// <param name="message">Exception message to provide further information.</param>
        /// <param name="inner">Inner Exception.</param>
        public InsecureOperationException(string message, Exception inner) 
            : base(message, inner) {}
    }
}