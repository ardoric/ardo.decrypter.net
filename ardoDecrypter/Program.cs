using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace ardoDecrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = readKey("private.key");
            if (args.Length >= 1)
            {
                foreach (string arg in args)
                {
                    Console.WriteLine(decrypt(key, arg));
                }
                return;
            }


            Dictionary<string, string> entries = readEncryptedEntries("server.hsconf");
            foreach (string hs_key in entries.Keys)
            {
                Console.WriteLine(hs_key + " " + decrypt(key, entries[hs_key]));
            }
        }

        private static byte[] decrypt_bytes(byte[] key, byte[] iv, byte[] ciphertext)
        {
            using (Aes crypto = new AesManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
            {
                crypto.IV = iv;
                crypto.Key = key;
                using (MemoryStream output = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(output, crypto.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(ciphertext, 0, ciphertext.Length);
                    }
                    return output.ToArray();
                }

            }
        }

        public static string decrypt(string key, string encrypted_text)
        {
            if (!encrypted_text.StartsWith("$2$"))
                throw new Exception("can't decrypt");

            byte[] the_key = Convert.FromBase64String(key);
            byte[] iv = Convert.FromBase64String(encrypted_text.Substring(3, 24));
            byte[] ciphertext = Convert.FromBase64String(encrypted_text.Substring(3 + 24));

            return Encoding.UTF8.GetString(decrypt_bytes(the_key, iv, ciphertext));
        }

        private static string readKey(string filename)
        {
            foreach (string line in File.ReadAllLines("private.key"))
            {
                string trimmed = line.Trim();
                if (trimmed.Equals(String.Empty) || trimmed.StartsWith("--"))
                    continue;
                return trimmed;
            }
            return "";
        }

        private static Dictionary<string, string> readEncryptedEntries(string filename)
        {
            using (Stream file_reader = File.OpenRead(filename)) {
                Dictionary<string, string> res = new Dictionary<string, string>();
                XDocument xml_doc = XDocument.Load(file_reader);
                foreach (XElement e in xml_doc.Descendants().Where( e => e.Attribute("encrypted") != null && e.Attribute("encrypted").Value.ToLower() == "true"))
                {
                    res.Add(e.Name.LocalName, e.Value);
                }
                return res;
            }
        }
    }
}
