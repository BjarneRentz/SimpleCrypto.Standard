using System;
using SimpleCrypto.Standard;

namespace SimpleCrypto.ConsoleSample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var pbkdf2 = new Pbkdf2();
            
            Console.WriteLine("Welcome! First you need to register...");
            Console.Write("  Username: ");
            string storedUsername = Console.ReadLine();

            Console.Write("  Password: ");
            string passwordPlaintext = ReadPassword();
            string storedPasswordHash = pbkdf2.Compute(passwordPlaintext);

            Console.WriteLine("\nThank you for registering, you can now login below...");
            Console.Write("  Username: ");
            string username = Console.ReadLine();

            Console.Write("  Password: ");
            string password = ReadPassword();
            
            string passwordHash = pbkdf2.Compute(password);

            if (storedUsername == username && pbkdf2.Compare(storedPasswordHash, passwordHash))
            {
                Console.WriteLine("\nLogin was successful!");
            }
            else
            {
                Console.WriteLine("\nLogin failed");
            }

            Console.WriteLine("\nPress any key to continue...");
            Console.Read();
        }

        private static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo keyInfo;

            do
            {
                keyInfo = Console.ReadKey(true);
                
                if (keyInfo.Key != ConsoleKey.Enter)
                {
                    password += keyInfo.KeyChar;
                    Console.Write("*");
                }
            }
            while (keyInfo.Key != ConsoleKey.Enter);

            Console.WriteLine("");
            return password;
        }
    }
}
