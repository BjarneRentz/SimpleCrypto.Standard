namespace SimpleCrypto.Standard.Exceptions
{
    public static class InsecureMessages
    {
        public  const string SALT_TO_SHORT = "Salt size should be at least 8 Bytes!";
        
        public const string HASH_SIZE_TO_BIG = "Hash size should not be greater than the output size of the used HMAC!";
        
        public const string HASH_SIZE_TO_SMALL = "Hash size should be greater than the size of the Salt!";
        
        public const string NOT_ENOUGH_ITERATIONS = "Iterations should be at least 10 000!";
    }
}