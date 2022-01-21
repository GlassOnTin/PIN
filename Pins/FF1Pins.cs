using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using FPE.Net;

namespace PIN
{
    /// <summary>
    /// A Pins Enumerable class that yields Personal Identification Numbers (PINs) selected from an FF1 encrypted sequence of PIN numbers.
    /// FF1 is a format-preserving encryption specified in NIST Special Publication 800-38G, 
    /// For further information see FPE.Net (https://github.com/a-tze/FPE.Net)
    /// Obvious PINs (those with only repeated or sequential digits) are skipped.
    /// </summary>
    public class FF1Pins : Pins, IEnumerable<string>
    {
        /// <summary>
        /// The Format-preserving encryption (FPE) method used to provide a cryptographically random sequence of PINs
        /// </summary>
        protected readonly FF1 ff1;

        // Create byte array for additional entropy when using Protect method.
        static byte[] additionalEntropy = { 189, 252, 159, 140, 48 };

#pragma warning disable CA1416 // ProtectedData only valid in windows platform
        /// <summary>
        /// The AES Key used to provide the encrypted sequence of PINs.  The key is stored in protected memory
        /// </summary>
        protected byte[] aesKey
        {
            set => _aesKey = ProtectedData.Protect(value, additionalEntropy, DataProtectionScope.CurrentUser);
            get => ProtectedData.Unprotect(_aesKey, additionalEntropy, DataProtectionScope.CurrentUser);
        }
        private byte[] _aesKey;
#pragma warning restore CA1416 // ProtectedData only valid in windows platform

        /// <summary>
        /// Generates Personal Identification Numbers (PINs) made from characters from the specified set.
        /// The PINs are selected from an encrypted sequence of PIN numbers.
        /// Obvious PINs (those with only repeated or sequential digits) are skipped in the sequence.  
        /// </summary>
        /// <param name="characterSet">A string of ordered and distinct characters to use when generating the PIN</param>
        public FF1Pins(byte[] aesKey, int startingIndex = 0, int length = 4, string characterSet = "0123456789")
        : base(startingIndex, length, characterSet)
        {
            // Store the key in a a private protected memory field
            this.aesKey = aesKey;
            
            // Prepare the format preserving encryption method
            // radix is the number of symbols used for each number of the pin, so radix = 10 for the digits 0 to 9.
            // maxTlen is only if we are using the "Tweak" functionality which is not used here.            
            ff1 = new FF1(radix: radix, maxTlen: 0);
        }

        /// <summary>
        /// Calculates a PIN from an encrypted sequence of PINs.
        /// Obvious pins are removed from the sequence, so...
        /// including "0001", "0002", "0003" ... "9998", "9999"
        /// excluding "0000", "1111", "3456", "7654" etc. repeated digits or simple sequences
        /// </summary>       
        /// <returns>Yields the next PIN in the sequence or yield break once all PINs in the sequence have been returned</returns>
        public override IEnumerator<string> GetEnumerator()
        {
            int index = startingIndex;
            byte[] tweak = new byte[0];
            int[] pin;
            while (true)
            {
                if (index >= LastIndex)
                {
                    yield break;
                }

                pin = PossiblyObviousPINIndices(index, length);
                pin = ff1.encrypt(aesKey, tweak, pin);
                
                if (!IsObvious(pin))
                {
                    yield return CharacterIndicesToString(pin);
                }                
                index++;
            };
        }
    }
}
