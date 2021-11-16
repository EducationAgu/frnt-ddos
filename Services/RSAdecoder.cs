﻿using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WebApi.Services
{
    public class RSAdecoder
    {
        private string privateKey = "-----BEGIN RSA PRIVATE KEY-----"
+ "MIIEpAIBAAKCAQEAskgPKBcNpz71mi4NSYa5mazJrO0WZim7T2yy7qPxk2NqQE7O"
+ "mWWakLJcaeUYnI0kO3yC57vck66RPCjKxWuWSGZ7dHXe0bWb5IXjcT4mNdnUIalR"
+ "+lV8czsoH/wDUvkQdG1SJ+IxzW64WvoaCRZ+/4wBF2cSUh9oLwGEXiodUJ9oJXFZ"
+ "VPKGCEjPcBI0vC2ADBRmVQ1sKsZg8zbHN+guU9rPLFzN4YNrCnEsSezVw/W1FKVS"
+ "8J/Xx4HSSg7AyVwniz8eHi0e3a8VzFg+H09I5wK+w39sjDYfAdnJUkr6PjtSbN4/"
+ "Sg/NMkKB2Ngn8oj7LCfe/7RNqIdiS+dQuSFgeQIDAQABAoIBAQCtAyEyVqz5UTAn"
+ "n+llIUmcyQIuvyatnnIYcfRzgsY9soy6O8BjPSbypSTp31ozEwXGdN7U5Ir7Br4L"
+ "E8s0K2R8fnfwXTMPcJ8I9qXyj82lFO+4ewkDV1KewRn/cCIJs4s0caL48ZpDMt/V"
+ "6kC58QruFIA6pdwxtij09RPwDg7E3U1MrL9PqgGXXQcAwtboP7gHs2ac+0b6CwV0"
+ "Cyev09Xpni3ID0iKX8yKsxi6wOh+2O4Mz8B3R2gIXq7Gzw8oeho0nSBD19B7fWs+"
+ "w4vFlHIl57zbeISQK10cvvJ8BB4byy/bn5V2O2lESgU10d48csD5IUcjdV4/yuFx"
+ "vI8S9vfBAoGBAOqbw03WXnhZQu8O7Gos8P7lrBi3eYdF45hHAfWbK5ub6O7fC0kQ"
+ "FYZqO0AR7oEAzuApWP0uGxQFALZ0QPyFZbpnKinE9T9a4M5AaP1Ex8WmeWbto96b"
+ "md6jVRXKXz24x5GDk+UdF7PJF91DufpUB5ZaO/AXpB9/3R9BDu7JHTjzAoGBAMKJ"
+ "grfZmyH3B9Cslnb8HUSlbXZQ/tnLoc3DpXnaENpYKWz/FMjqxTHuVRRqH86tYL33"
+ "/ow3UCaN3EYgIguoVC+DTbzk3/I9IXXeDXrocH1qCUy+x6dohzPoKZMoILLs+VeF"
+ "eAJfIptgVIfcD5teKdEY4lYPbV0m47Q2ET8pgNvjAoGADWgDPBJw6Y2oPoLqzZJt"
+ "3xL+x5bMcgdzXwNHwGIylrzNDcFfIrixkjHF2v5rU6HZMIQMWsNktrsmdEamZAe3"
+ "bXRxu1tO7GTkDcUuerKQe+HsdA5GW/UmUMuilBExahSCCvWq4N/Nt+9Y1sMFAKIG"
+ "oPfdDvY64bXry9pq4QhLDDMCgYAGs9ovH24641n/lJKyksknXlPBKdU+B8gRYNZI"
+ "tnyyKSt0N+2tZnlY2Q9RXr6tzkdxBCRfDGDUkzqtp9nEcQ5FfM6m3XPh0r1eZEIu"
+ "o+eMSqT7Ye9bEzzlSvBzw4Qs5gFJRK331vNISy9eZvSas8nZDHRv5qQr+3UI9nvt"
+ "oy5vZQKBgQCK5z2IeL1NFd5OuJaR07Y+xwO7IOiZ+nn+fXWYkZ4bD08Dg0ACnd/w"
+ "OcS+2fU2/IIuXnhT/f5M5r0AJI1lG/V8TBo4gxN2dm7yBLgczbK3u+tex+pEnfEZ"
+ "qxAE0159q3iGvU5nmtX6VC0Z/IJIUCVgiEMwoKct0T5eOV2iQf5PaQ=="
+ "-----END RSA PRIVATE KEY-----";


        private readonly RSACryptoServiceProvider _privateKey;

        public RSAdecoder()
        {
            _privateKey = GetPrivateKeyFromPemFile(privateKey);
        }

        public string Decrypt(string encrypted)
        {
            var decryptedBytes = _privateKey.Decrypt(Convert.FromBase64String(encrypted), false);
            return Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length);
        }

        private RSACryptoServiceProvider GetPrivateKeyFromPemFile(string key)
        {
            using (TextReader pktr = new StringReader(key))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(pktr).ReadObject();

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }

        private RSACryptoServiceProvider GetPublicKeyFromPemFile(String key)
        {
            using (TextReader publicKeyTextReader = new StringReader(key))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParam);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }
    }
}