using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace PIN
{
    /// <summary>
    /// Static method to securely store a key in the registry
    /// </summary>
    internal static class KeyStore
    {
        /// <summary>
        /// Stores a key securely in the registry
        /// </summary>
        public static void StoreKey(string keyName, string subKey, string valueName, byte[] key, DataProtectionScope dpScope)
        {
            // Store key to protected byte array.  
            byte[] encryptedKey = ProtectedData.Protect(key, null, dpScope);

            // Create a security context.  
            string user = Environment.UserDomainName + "\\" + Environment.UserName;
            RegistrySecurity security = new RegistrySecurity();
            RegistryAccessRule rule = new RegistryAccessRule(user
                                                            , RegistryRights.FullControl
                                                            , InheritanceFlags.ContainerInherit
                                                            , PropagationFlags.None
                                                            , AccessControlType.Allow);
            // Add rule to RegistrySecurity.  
            security.AddAccessRule(rule);

            // Create registry key and apply security context   
            Registry.CurrentUser.CreateSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, security);

            // Write the encrypted connection string into the registry  
            Registry.SetValue(keyName + @"\" + subKey, valueName, encryptedKey);
        }

        /// <summary>
        /// Retrieves a key from the registry and decrypts using DPAPI  
        /// </summary>
        public static byte[] ReadKey(string keyName, string subKey, string valueName)
        {
            
            var rv = Registry.GetValue(keyName + @"\" + subKey, valueName, null);
            if (rv == null) return null;
            byte[] encryptedKey = rv as byte[];

            // Unprotect data.  
            return ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
        }
    }
}
