# PIN
A C# .NET Core class library to securely generate PINs using the FF1 Format-Preserving-Encryption (FPE) algorithm.  

The PIN namespace contains the FF1Pins class with an IEnumerable<string> interface.  An AES key and the FF1 algorithm determine the order of the enumerated PIN sequence.

## Example usage
```
// Generate an AES key
Aes aes = Aes.Create();
aes.GenerateKey();

// Create a secure PIN enumerable that can yield a sequence of non-obvious and distinct PINs from an encrypted sequence
var ff1Pins = new FF1Pins(aes.Key);

// Create five non-obvious PINs            
foreach (string pin in ff1Pins.Take(5))
{
    Console.WriteLine(pin);
}
```

## Additional options
The length of the PIN, the character set, and a starting index of the enumerator can be specified in the constructor:
```
public FF1Pins(byte[] aesKey, int startingIndex = 0, int length = 4, string characterSet = "0123456789")
```

## How it works
A Format-Preserving-Encryption (FPE) algorithm takes a string of characters as input.  The encrypted output has the same number of characters as the input and the characters of the encrypted output are from the same character set as the input.  
  
The library includes an enumerable Pins class that yields a simple ordered sequence of PIN numbers.  The enumerator skips obvious PINs such as "2222", "3456", or "9876".  The enumerator will also yield-break after all PINs have been generated from the sequence, however the Enumerable could be reset if repeated PINs are acceptable. 
  
The FF1Pins class inherits from the Pins class but also includes an FF1 encrpyption step.  If the encrypted pin is obvious, then it is again skipped from the sequence.  A property of the encryption algorithm is that the sequence of PINs will be different for any supplied AES key.
