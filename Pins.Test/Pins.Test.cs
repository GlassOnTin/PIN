using Xunit;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace PIN.Test
{
    public class PinsTest
    {
        /// <summary>
        /// Asserts that Pins.PossiblyObviousPIN method generates the expected simple sequence of PINs
        /// </summary>
        [Fact]
        public void testPossiblyObviousPIN()
        {
            // Create a plain PIN enumerable that yields a sequence of non-obvious pins
            var pins = new Pins();

            // Test that all the PossiblyObviousPINs are as expected 
            for (int i = 0; i < 9999; i++)
            {
                string expected = $"{i:D4}";
                string actual = pins.PossiblyObviousPIN(i, 4);
                Assert.Equal(expected, actual);
            }
        }

        /// <summary>
        /// Tests Pins.IsObvious
        /// </summary>
        [Fact]
        public void testIsObvious()
        {
            // Create a plain PIN enumerable that yields a sequence of non-obvious pins
            var pins = new Pins();

            // Assert that a non-obvious PIN gives returns false
            Assert.False(pins.IsObvious(new int[] { 0, 2, 4, 6 }));

            for (int i=0; i<9; i++)
            {
                // Assert that when all the characters are the same that the PIN is obvious
                Assert.True(pins.IsObvious(new int[] { i, i, i, i }));

                // Assert that when all the characters are in sequence that the PIN is obvious
                if (i >= 3)
                {
                    Assert.True(pins.IsObvious(new int[] { i - 3, i - 2, i - 1, i }));
                    Assert.True(pins.IsObvious(new int[] { i, i - 1, i - 2, i - 3 }));
                }
            }
        }

        /// <summary>
        /// Asserts that Pins enumerable is empty when starting index greater than the number of PINs
        /// </summary>
        [Fact]
        public void testBadStartIndex()
        {
            // Create a Pins enumerable with starting index greater than the number of PINs
            var pins = new Pins(20000);

            // Assert that pins is empty
            Assert.Empty(pins.Take(1));
        }

        /// <summary>
        /// Asserts that Pins and FF1Pins create the same set of PIN but in different orders
        /// </summary>
        [Fact]
        public void testFF1EqualsPins()
        {
            // Create a plain PIN enumerable that can yield a sequence of non-obvious pins
            var pins = new Pins();

            // Create a set of all non-obvious PINs
            HashSet<string> allPIN = new HashSet<string>();
            foreach (string pin in pins)
            {
                allPIN.Add(pin);
            }

            // Generate an AES key to test the secure PIN generator
            Aes aes = Aes.Create();
            aes.GenerateKey();

            // Create a secure PIN enumerable that can yield a sequence of non-obvious pins from an encrypted sequence
            var ff1Pins = new FF1Pins(aes.Key);

            // Create a set of all non-obvious PINs
            HashSet<string> allSecurePIN = new HashSet<string>();
            foreach (string pin in ff1Pins)
            {
                allSecurePIN.Add(pin);
            }

            // The secure PIN set should countain all the same elements as the simply PIN set
            Assert.True(allPIN.SetEquals(allSecurePIN));
        }

        /// <summary>
        /// Asserts that that FF1Pins only yields unique PINs and creates a different sequence of PINs for different keys
        /// </summary>
        [Fact]
        public void testFF1PinsDistinctAndChanging()
        {
            // Generate two AES keys to test the secure PIN generator
            Aes aes1 = Aes.Create();
            Aes aes2 = Aes.Create();
            aes1.GenerateKey();        
            aes2.GenerateKey();            

            // Create two secure PIN enumerable that can yield a sequence of non-obvious pins from an encrypted sequence
            var ff1Pins1 = new FF1Pins(aes1.Key);
            var ff1Pins2 = new FF1Pins(aes2.Key);

            // Create a List of all non-obvious encrypted PINs using the first key
            List<string> allSecurePIN1 = new List<string>();            
            foreach (string pin in ff1Pins1)
            {
                allSecurePIN1.Add(pin);
            }

            // Create a List of all non-obvious encrypted PINs using the second key
            List<string> allSecurePIN2 = new List<string>();
            foreach (string pin in ff1Pins2)
            {
                allSecurePIN2.Add(pin);
            }

            // Test that both sets only contain only distinct PINs
            int d1 = allSecurePIN1.Distinct().ToList().Count;
            int d2 = allSecurePIN2.Distinct().ToList().Count;
            Assert.Equal(d1, allSecurePIN1.Count);
            Assert.Equal(d2, allSecurePIN2.Count);

            // Test that both sets contain the same PINs
            Assert.True(allSecurePIN1.ToHashSet().SetEquals(allSecurePIN2));
        }

        /// <summary>
        /// Asserts that that FF1Pins only yields unique PINs and creates a different sequence of PINs for different keys
        /// </summary>
        [Fact]
        public void testFF1PersistancePins()
        {
            // Create a plain PIN enumerable that can yield a sequence of non-obvious pins
            var pins = new Pins();

            // Create a set of all non-obvious PINs
            HashSet<string> allPIN = new HashSet<string>();
            foreach (string pin in pins)
            {
                allPIN.Add(pin);
            }

            // Create a secure PIN enumerable that can yield a sequence of non-obvious pins from an encrypted sequence
            var ff1Pins = new FF1PersistantPins();

            // Create a List of all non-obvious encrypted PINs that contains twice as many PINs as the plain PIN enumerable
            List<string> allSecurePIN = new List<string>();            
            foreach (string pin in ff1Pins.Take(2*allPIN.Count))
            {
                allSecurePIN.Add(pin);
            }

            // Assert that allSecurePIN contains the same set of PIN as the plain PINs
            Assert.True(allSecurePIN.ToHashSet().SetEquals(allPIN));
        }
    }
}
