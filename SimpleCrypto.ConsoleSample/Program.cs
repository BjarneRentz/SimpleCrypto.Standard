using System;
using CommandLine;
using SimpleCrypto.Standard;

namespace SimpleCrypto.ConsoleSample
{
    [Verb("compute", HelpText = "Compute hash value of plaintext")]
    public class ComputeOptions
    {
        [Value(0, Required = true, HelpText = "Plaintext to be hashed")]
        public string Plaintext { get; set; }

        [Option(HelpText = "Salt to use for hashing")]
        public string Salt { get; set; }
    }

    public class Program
    {
        public static int Main(string[] args)
        {
            return CommandLine.Parser.Default.ParseArguments<ComputeOptions>(args)
                .MapResult(
                    (ComputeOptions opts) => RunCompute(opts),
                    errs => 1);
        }

        private static int RunCompute(ComputeOptions options)
        {
            var pbkdf2 = new Pbkdf2 { PlainText = options.Plaintext };
            Console.WriteLine($"Plain Text: {options.Plaintext}");

            if (!string.IsNullOrWhiteSpace(options.Salt))
            {
                pbkdf2.Salt = options.Salt;
                Console.WriteLine($"Salt: {options.Salt}");
            }

            string hashedText = pbkdf2.Compute();
            Console.WriteLine($"Hashed Text: {hashedText}");

            return 0;
        }
    }
}
