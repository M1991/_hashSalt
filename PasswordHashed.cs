public class PasswordHashed
    {
        public const int SALT_BYTES = 24;
        public const int HASH_BYTES = 24;
        public const int PBKDF2_ITERATIONS = 1000;

        public const int ITERATION_INDEX = 0;
        public const int SALT_INDEX = 1;
        public const int PBKDF2_INDEX = 2;

        /* <summary>
         Creates a salted PBKDF2 hash of the password.
        </summary>
        <param name="password">The password to hash.</param>
        <returns>The hash of the password.</returns>
         * 
         */

        public static string CreateHash(string password)
        {
            var cryptoProvider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[SALT_BYTES-1];
            cryptoProvider.GetBytes(salt);
            // Hash the password and encoded password
            var hash = GetPbkdf2Bytes(password, salt, PBKDF2_ITERATIONS, HASH_BYTES);
            return PBKDF2_ITERATIONS + ":" +
                   Convert.ToBase64String(salt) + ":" +
                   Convert.ToBase64String(hash);
        }

        /*
        Validates a password given a hash of the correct one.
        </summary>
        <param name="password">The password to check.</param>
        <param name="goodHash">A hash of the correct password.</param>
        <returns>True if the password is correct. False otherwise.</returns>
        */

        public static bool ValidatePassword(string password, string correctHash)
        {
            char[] delimiter = { ':' };
            var split = correctHash.Split(delimiter);
            var iterations = Int32.Parse(split[ITERATION_INDEX]);
            var salt = Convert.FromBase64String(split[SALT_INDEX]);
            var hash = Convert.FromBase64String(split[PBKDF2_INDEX]);

            var testHash = GetPbkdf2Bytes(password, salt, iterations, hash.Length);
            return SlowEquals(hash, testHash);
        }

        /*
        Compares two byte arrays in length-constant time. This comparison
        method is used so that password hashes cannot be extracted from 
        on-line systems using a timing attack and then attacked off-line.
        </summary>
        <param name="a">The first byte array.</param>
        <param name="b">The second byte array.</param>
        <returns>True if both byte arrays are equal. False otherwise.</returns>
             * * 
         */

        private static bool SlowEquals(byte[] a, byte[] b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        /*
         * 
         * <summary>
            Computes the PBKDF2-SHA1 hash of a password.
        </summary>
        <param name="password">The password to hash.</param>
        <param name="salt">The salt.</param>
        <param name="iterations">The PBKDF2 iteration count.</param>
        <param name="outputBytes">The length of the hash to generate, in bytes.</param>
        <returns>A hash of the password.</returns>
         * 
         */

        private static byte[] GetPbkdf2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            // Here Object initialization is simplified
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt);
            pbkdf2.IterationCount = iterations;
            return pbkdf2.GetBytes(outputBytes);
        }
    }
