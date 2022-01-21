using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace PIN
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create a secure PIN enumerable that can yield a sequence of non-obvious pins from an encrypted sequence
            var ff1Pins = new FF1PersistantPins();

            // Output a single PIN from the sequence
            foreach (var pin in ff1Pins.Take(1))
            {
                Console.WriteLine(pin);
            }
        }       
    }
}
