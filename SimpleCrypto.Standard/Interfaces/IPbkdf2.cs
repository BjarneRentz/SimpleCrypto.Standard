using System;
using SimpleCrypto.Standard.Exceptions;

namespace SimpleCrypto.Standard.Interfaces
{

    /// <summary>
    /// Interface for the PBKDF2 implementation.
    /// </summary>
    public interface IPbkdf2
    {
        /// <summary>
        /// Number of hash iterations.
        /// </summary>
        int HashIterations { get; set; }

        /// <summary>
        /// Size of the <see cref="Salt"/> in Bytes if no salt is set.
        /// </summary>
        int SaltSize { get; set; }

        /// <summary>
        /// Plaintext to be hashed.
        /// </summary>
        string PlainText { get; set; }

        /// <summary>
        /// The base64 encoded hash of the <see cref="PlainText"/>
        /// </summary>
        string HashedText { get; }

        /// <summary>
        /// Salt that will be used for computing the <see cref="HashedText"/>. This contains both Salt and HashIterations separated by a dot.
        /// </summary>
        string Salt { get; set; }
        
        /// <summary>
        /// The size of <see cref="HashedText"/>
        /// </summary>
        int HashSize { get; set; }
        
        /// <summary>
        /// Computes the hash and saves it in <see cref="HashedText"/>. If no <see cref="Salt"/> is set, it will generate it.
        /// </summary>
        /// <returns>The computed hash.</returns>
        /// <exception cref="InvalidOperationException">Gets thrown when the <see cref="PlainText"/> is not set (null or empty).</exception>
        /// <exception cref="InsecureOperationException">Gets thrown when insecure conditions are set at the time of computing the hash.</exception>
        string Compute();

        /// <summary>
        /// Computes the hash and saves it in <see cref="HashedText"/>. If no <see cref="Salt"/> is set, it will generate it.
        /// </summary>
        /// <param name="textToHash">Plaintext that gets hashed.</param>
        /// <returns>The computed hash.</returns>
        string Compute(string textToHash);

        /// <summary>
        /// Computes the hash and saves it in <see cref="HashedText"/>. If no <see cref="Salt"/> is set, it will generate it.
        /// </summary>
        /// <param name="textToHash">Plaintext that gets hashed.</param>
        /// <param name="salt">The salt to be used in the computation. Contains the number of iterations and the real salt separated by a dot.</param>
        /// <returns>The computed hash.</returns>
        string Compute(string textToHash, string salt);
        
        /// <summary>
        /// Computes the hash and saves it in <see cref="HashedText"/>. If no <see cref="Salt"/> is set, it will generate it.
        /// </summary>
        /// <param name="textToHash">Plaintext that gets hashed</param>
        /// <param name="saltSize">The size of the salt that gets generated</param>
        /// <param name="hashIterations">Number of iterations PBKDF2 does.</param>
        /// <returns>The computed hash.</returns>
        string Compute(string textToHash, int saltSize, int hashIterations);

        /// <summary>
        /// Generates a salt with default salt size and iterations
        /// </summary>
        /// <returns>The generated Salt.</returns>
        string GenerateSalt();

        /// <summary>
        /// Generates a salt
        /// </summary>
        /// <param name="hashIterations">The hash iterations used to compute the hash.</param>
        /// <param name="saltSize">The size of the salt</param>
        /// <returns>The generated salt</returns>
        /// <exception cref="InvalidOperationException">Salt size is lower than 1.</exception>
        string GenerateSalt(int hashIterations, int saltSize);

        /// <summary>
        /// Get the time in milliseconds it takes to complete the hash for the iterations
        /// </summary>
        /// <param name="iteration"></param>
        /// <returns>The elapsed time.</returns>
        [Obsolete("This method will not be available in the next major release!")]
        int GetElapsedTimeForIteration(int iteration);
        
        /// <summary>
        /// Compares the given Strings for equality in a constant time.
        /// </summary>
        /// <param name="passwordHash1">The first password hash to compare</param>
        /// <param name="passwordHash2">The second password hash to compare</param>
        /// <returns>true: indicating the password hashes are the same, false otherwise.</returns>
        bool Compare(string passwordHash1, string passwordHash2);
    }
}
