#region - Using Statements -

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Encryption;

#endregion

namespace TestConsole
{
    class Program
    {

        #region - UI Methods -

        static void Main(string[] args)
        {
            TestEncryption();
            End();
        }

        static void End()
        {
            Console.WriteLine();
            Console.Write("Press any key to exit...");
            Console.ReadKey(true);
        }

        #endregion

        #region - Testing Methods -

        static void TestEncryption()
        {
            string key = "farted";
            string salt = "stainz";

            using (Crypto encryption = new Crypto(key, salt))
            {
                Console.WriteLine("Enter something to encrypt:");
                string valueToEncrypt = Console.ReadLine();

                string encrypted = encryption.Encrypt(valueToEncrypt);
                Console.WriteLine(encrypted);

                string decrypted = encryption.Decrypt(encrypted);
                Console.WriteLine(decrypted);
            }
        }

        #endregion

    }
}
