using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PIN
{
    /// <summary>
    /// An Enumerable class that yields Personal Identification Numbers (PINs) strings from a simple sequence.
    /// Obvious PINs (those with only repeated or sequential digits) are skipped ins the sequence.  
    /// </summary>
    public class Pins : IEnumerable<string>
    {
        /// <summary>
        /// The index of the first PIN to yield
        /// </summary>
        protected int startingIndex;

        /// <summary>
        /// The number of characters in the PIN
        /// </summary>
        protected readonly int length;

        /// <summary>
        /// A set of characters used for the digits of the PIN.
        /// </summary>        
        protected readonly List<char> characterSet;

        /// <summary>
        /// The number of distinct characters used to generate a PIN
        /// </summary>
        protected readonly int radix;

        /// <summary>
        /// Returns the largest index after which there are no more PINs
        /// </summary>
        public int LastIndex
        {
            get => (int)(Math.Pow(radix, length));
        }

        public Pins(int startingIndex = 0, int length = 4, string characterSet = "0123456789")
        {
            // The index of the first PIN to yield
            if (startingIndex < 0) startingIndex = 0;
            this.startingIndex = startingIndex;

            // The number of characters in the PIN
            this.length = length;

            // Create an indexible list of distinct characters
            this.characterSet = new List<char>(characterSet.ToCharArray().Distinct());
            radix = this.characterSet.Count;

            // Check if the specified character set has repeated characters
            if (radix == 0 || radix < characterSet.Length)
            {
                throw new ArgumentException("There must by no repeated characters in the set", nameof(characterSet));
            }
        }

        /// <summary>
        /// The Current PINs in a simple sequence order.
        /// This method should be overridden by a secure PINgenerator
        /// Obvious pins are removed from the sequence, so...
        /// including "0001", "0002", "0003" ... "9998", "9999"
        /// excluding "0000", "1111", "3456", "7654" etc. repeated digits or simple sequences
        /// </summary>
        /// <returns>Yields the next PIN in the sequence or yield break once all PINs in the sequence have been returned</returns>
        public virtual IEnumerator<string> GetEnumerator()
        {
            int index = startingIndex;

            int[] pin;
            while (true)
            {
                if (index >= LastIndex)
                {
                    yield break;
                }

                pin = PossiblyObviousPINIndices(index, length);

                if (!IsObvious(pin))
                {
                    yield return CharacterIndicesToString(pin);
                }                
                index++;
            };
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Tests if a PIN is obvious, for example "3333" or "1234" or "7654".
        /// </summary>
        /// <param name="pin">An array of character indices to check</param>
        /// <returns>True if the pin contains only repeated or sequential digits</returns>
        internal protected bool IsObvious(int[] pin)
        {
            // Calculate the difference between the first two characters
            int firstDifference = pin[1] - pin[0];

            // If the first two digits are more than one value different, the pin is not obvious, e.g. "1333" or "3111" 
            if (Math.Abs(firstDifference) > 1) return false;

            // Use the Aggregate method to sum the neigbouring character differences compared to the first character difference
            // If all the digits are the same then:                 firstDifference = (b-a) = 0
            // If all the digits are in increasing sequence then:   firstDifference = (b-a) = +1
            // If all the digits are in decreasing sequence then:   firstDifference = (b-a) = -1
            int totalDifferenceFromFirst = 0;
            for (int i = 2; i < length; i++)
            {                
                totalDifferenceFromFirst += pin[i] - pin[i-1] - firstDifference;
            }

            // The PIN is obvious if all the digit neighbours were all the same in sequence or the
            return totalDifferenceFromFirst == 0;
        }

        /// <summary>
        /// Generates a possibly obvious PIN from the simple numeric sequence of PINs
        /// </summary>
        /// <param name="index">The index of the PIN in the sequence</param>
        /// <param name="length">The number of symbols required</param>
        /// <returns>An array of character indices of the pin</returns>
        internal protected int[] PossiblyObviousPINIndices(int index, int length = 4)
        {
            int[] result = new int[length];
            do
            {
                result[--length] = index % radix;
                index /= radix;
            }
            while (length > 0 && index > 0);
            return result;
        }

        // <summary>
        /// Generates a possibly obvious PIN from the simple numeric sequence of PINs
        /// </summary>
        /// <param name="index">The index of the PIN in the sequence</param>
        /// <param name="length">The number of symbols required</param>
        /// <returns>A string containing the PIN</returns>
        internal string PossiblyObviousPIN(int index, int length = 4)
        {
            int[] indices = PossiblyObviousPINIndices(index, length);
            return CharacterIndicesToString(indices);
        }

        /// <summary>
        /// Maps an array of character indicies to a string, 
        /// where the indices are the position of characters in characterSet
        /// </summary>
        /// <param name="indices"></param>
        /// <returns></returns>
        internal protected string CharacterIndicesToString(int[] indices)
        {
            StringBuilder sb = new StringBuilder();
            foreach (int i in indices)
            {
                sb.Append(characterSet[i]);
            }
            return sb.ToString();
        }
    }    
}
