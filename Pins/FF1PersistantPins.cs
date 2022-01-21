using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PIN
{
    /// <summary>
    /// A Pins Enumerable class that yields Personal Identification Numbers (PINs) selected from an FF1 encrypted sequence of PIN numbers.
    /// The key for the PIN sequence is automatically generated and stored securely in the registry along with the index.
    /// 
    /// FF1 is a format-preserving encryption specified in NIST Special Publication 800-38G, 
    /// For further information see FPE.Net (https://github.com/a-tze/FPE.Net)
    /// Obvious PINs (those with only repeated or sequential digits) are skipped.
    /// </summary>
    public class FF1PersistantPins : FF1Pins, IEnumerable<string>
    {
        const string keyName = @"HKEY_CURRENT_USER";
        const string subKey = @"PIN";
        const string valueName = "KeyData";

        public FF1PersistantPins(int length = 4, string characterSet = "0123456789")        
        : base(new byte[32], 0, length, characterSet)
        {
            PrepareKeyAndIndex(out byte[] key, out int index);
            
            aesKey = key;
            startingIndex = index;
        }

        /// <summary>
        /// Calculates a PIN from an encrypted sequence of PINs.  
        /// Once all the PINs are exhausted, the key and index are reset.
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
                    PrepareKeyAndIndex(out byte[] key, out index, reset: true);
                    aesKey = key;
                    startingIndex = index;
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

        private static void PrepareKeyAndIndex(out byte[] key, out int index, bool reset = false)
        {
            index = 0;
            byte[] bIndex;

            // Read the key and index from the registry if they were already created for the current user
            byte[] keyAndIndex = KeyStore.ReadKey(keyName, subKey, valueName);

            if (reset || keyAndIndex == null)
            {
                // Generate a new AES key
                Aes aes = Aes.Create();
                aes.GenerateKey();
                key = aes.Key;
            }
            else
            {
                // Separate the key from the index
                key = keyAndIndex.Take(keyAndIndex.Length - 4).ToArray();
                bIndex = keyAndIndex.Skip(keyAndIndex.Length - 4).ToArray();
                index = BitConverter.ToInt32(bIndex);

                // Increment the index
                index++;
            }

            // Concatenate the index with the key and store in the registry
            bIndex = BitConverter.GetBytes(index);
            keyAndIndex = key.Concat(bIndex).ToArray();
            KeyStore.StoreKey(keyName, subKey, valueName, keyAndIndex, DataProtectionScope.CurrentUser);
        }
    }


}
