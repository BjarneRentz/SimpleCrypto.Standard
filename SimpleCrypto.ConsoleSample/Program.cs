using System;
using SimpleCrypto.Standard;

namespace SimpleCrypto.ConsoleSample
{

    public class Program
    {
        public static void Main(string[] args)
        {
            const string SALT = "987654.Random";
            const int SALT_SIZE = 13;
            const int HASH_ITERATIONS = 123456;

            Pbkdf2 pbkdf2;
            string hashedText;

            Console.WriteLine("Example 1: calling Compute()");
            pbkdf2 = new Pbkdf2 { PlainText = "Example 1"};
            hashedText = pbkdf2.Compute();
            Console.WriteLine($"  Plain text:  {pbkdf2.PlainText}");
            Console.WriteLine($"  Hashed text: {hashedText}");

            Console.WriteLine("\nExample 2: calling Compute(textToHash)");
            pbkdf2 = new Pbkdf2();
            hashedText = pbkdf2.Compute("Example 2");
            Console.WriteLine($"  Plain text:  {pbkdf2.PlainText}");
            Console.WriteLine($"  Hashed text: {hashedText}");

            Console.WriteLine("\nExample 3: calling Compute(textToHash, salt)");
            pbkdf2 = new Pbkdf2();
            hashedText = pbkdf2.Compute("Example 3", SALT);
            Console.WriteLine($"  Plain text:  {pbkdf2.PlainText}");
            Console.WriteLine($"  Salt:        {SALT}");
            Console.WriteLine($"  Hashed text: {hashedText}");

            Console.WriteLine("\nExample 4: calling Compute(textToHash, saltSize, hashIterations)");
            pbkdf2 = new Pbkdf2();
            hashedText = pbkdf2.Compute("Example 4", SALT_SIZE, HASH_ITERATIONS);
            Console.WriteLine($"  Plain text:  {pbkdf2.PlainText}");
            Console.WriteLine($"  Salt size:   {SALT_SIZE}");
            Console.WriteLine($"  Iterations:  {HASH_ITERATIONS}");
            Console.WriteLine($"  Hashed text: {hashedText}");

            Console.WriteLine("\nPress any key to continue...");
            Console.Read();
        }
    }
}
