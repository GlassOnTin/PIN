using System;
using System.Linq;
using System.Security.Cryptography;

namespace PIN
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("An example of generating five PINs from an FF1 encrypted sequence:");

            // Generate an AES key to test the secure PIN generator
            Aes aes = Aes.Create();
            aes.GenerateKey();

            // Create a secure PIN enumerable that can yield a sequence of non-obvious pins from an encrypted sequence
            var ff1Pins = new FF1Pins(aes.Key);

            // Create a set of all non-obvious PINs            
            foreach (string pin in ff1Pins.Take(5))
            {
                Console.WriteLine(pin);
            }
        }
    }
}
