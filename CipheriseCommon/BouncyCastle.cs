
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

#if !CIPHERISE_COMMON_NO_BOUNCYCASTLE

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Cipherise.Common
{
    internal class CipheriseBouncyCastle
    {
        //RsaKeyParameters / AsymmetricKeyParameter;
        private RsaKeyParameters m_PrivateKey;
        private RsaKeyParameters m_PublicKey;

        private static AsymmetricCipherKeyPair GetKeyPair(int iKeySize)
        {
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom secureRandom = new SecureRandom(randomGenerator);
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(secureRandom, iKeySize);

            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        public bool GenerateKeyPair()
        {
            AsymmetricCipherKeyPair Keys = GetKeyPair(2048);
            m_PrivateKey = (RsaKeyParameters)Keys.Private;
            m_PublicKey = (RsaKeyParameters)Keys.Public;

            return (m_PrivateKey != null) && (m_PublicKey != null);
        }

        public void SetPublicKey(AsymmetricKeyParameter rsaDevicePubKey)
        {
            m_PublicKey = (RsaKeyParameters)rsaDevicePubKey;
        }

        public bool SetPEMPrivateKey(string strPEMPrivateKey)
        {
            AsymmetricCipherKeyPair Keys;
            if (strPEMPrivateKey.FromPem(out Keys) == false)
                return false;

            if ((Keys.Private == null) || (Keys.Public == null))
                return false;

            m_PrivateKey = (RsaKeyParameters)Keys.Private;
            m_PublicKey  = (RsaKeyParameters)Keys.Public;

            return true;
        }

        public bool SetPEMPublicKey(string strPEMPublicKey)
        {
            RsaKeyParameters PubKey;
            if (strPEMPublicKey.FromPem(out PubKey) == false)
                return false;

            if (PubKey.IsPrivate)
                return false;

            m_PublicKey = PubKey;
            return true;
        }

        public bool GetPublicKeyAsPEM(out string strPublicKey)
        {
            if (m_PublicKey != null)
                return m_PublicKey.ToPem(out strPublicKey);
            strPublicKey = null;
            return false;
        }

        public bool SignHexString(string strHexedData, out string strHexedSignature)
        {
            if (m_PrivateKey == null)
            {
                strHexedSignature = null;
                return false;
            }
            return m_PrivateKey.SignHexString(strHexedData, out strHexedSignature);
        }

        public bool VerifyHexString(string strHexedData, string strHexedSignature)
        {
            if (m_PublicKey == null)
                return false;
            return m_PublicKey.VerifyHexString(strHexedData, strHexedSignature);
        }

        public bool EncryptBuffer(byte[] aData, out string strHexedEncrypted)
        {
            if ((m_PublicKey == null) || (aData == null) || (aData.Length == 0))
            {
                strHexedEncrypted = null;
                return false;
            }
            return m_PublicKey.EncryptBuffer(aData, out strHexedEncrypted);
        }

        public bool DecryptBuffer(string strHexedEncrypted, out byte[] aData)
        {
            if ((m_PrivateKey == null) || (strHexedEncrypted == null) || (strHexedEncrypted.Length == 0))
            {
                aData = null;
                return false;
            }
            return m_PrivateKey.DecryptBuffer(strHexedEncrypted, out aData);
        }

        private static bool GetCipheriseSignatureHash(string strHostName, string strServiceID, string strUserName, string strDeviceID, string strDevicePublicKey, int iLevel, out string strHash)
        {
            if (   (String.IsNullOrEmpty(strHostName))
                || (String.IsNullOrEmpty(strServiceID))
                || (String.IsNullOrEmpty(strUserName))
                || (String.IsNullOrEmpty(strDeviceID))
                || (String.IsNullOrEmpty(strDevicePublicKey))
                )
            {
                strHash = null;
                return false;
            }

            //Remove unwanted chars from start and end.
            strHostName = strHostName.Trim(new char[] {' ','\\','/' });

            //Lower case.
            strHostName = strHostName.ToLower();
            strUserName = strUserName.ToLower();

            //Starts  with: http:// or https://
            //and trailing: /
            int iSlash = -1;
            if(strHostName.StartsWith("https://"))
                iSlash = 7;
            else if(strHostName.StartsWith("http://"))
                iSlash = 6;
            else
            {
                strHash = null;
                return false;
            }
            iSlash = strHostName.IndexOf('/', iSlash + 1);
            if(iSlash == -1)
                strHostName += "/"; 
            else
                strHostName = strHostName.Substring(0, iSlash + 1);

            //Remove default ports from host.
            if (-1 != strHostName.IndexOf(":443"))
                strHostName = strHostName.Replace(":443", "");
            if (-1 != strHostName.IndexOf(":80"))
                strHostName = strHostName.Replace(":80", "");

            if (strServiceID.Length < 16)
                strServiceID = strServiceID.PadLeft(16, '0');
            else if (strServiceID.Length > 16)
                strServiceID = strServiceID.Substring(strServiceID.Length - 16);

            if (strDeviceID.Length < 16)
                strDeviceID = strDeviceID.PadLeft(16, '0');
            else if (strDeviceID.Length > 16)
                strDeviceID = strDeviceID.Substring(strDeviceID.Length - 16);

            string strConcat = strHostName + strServiceID + strUserName + strDeviceID + strDevicePublicKey + iLevel.ToString();

            strHash = strConcat.SHA256();
            return true;
        }

        public bool GetCipheriseSignature(string strHostName, string strServiceID, string strUserName, string strDeviceID, string strDevicePublicKey, int iLevel, out string strSignature)
        {
            //RSA - SHA256 sign(SP private key, SHA256(hostname normalised to all lower case, serviceId, username normalised to all lower case, device id, device profile auth level public key, auth level))
            //hostname should contain fully qualified URL with the ending "/" included in it.

            string strHash;
            if (    (m_PrivateKey == null)
                ||  (false == GetCipheriseSignatureHash(strHostName, strServiceID, strUserName, strDeviceID, strDevicePublicKey, iLevel, out strHash)))
            {
                strSignature = null;
                return false;
            }

            return SignHexString(strHash, out strSignature);
        }

        public bool VerifyCipheriseSignature(string strHostName, string strServiceID, string strUserName, string strDeviceID, string strDevicePublicKey, int iLevel, string strSignature)
        {
            string strHash;
            if (    (m_PublicKey == null)
                ||  (String.IsNullOrEmpty(strSignature))
                ||  (false == GetCipheriseSignatureHash(strHostName, strServiceID, strUserName, strDeviceID, strDevicePublicKey, iLevel, out strHash)))
                return false;

            return VerifyHexString(strHash, strSignature);
        }

        public bool SaveToFile(string strFilename)
        {
            try
            {
                if ((m_PrivateKey == null) || (m_PublicKey == null))
                    return false;

                string strPrvHex, strPubHex;

                {
                    //m_PrivateKey to byte[]
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(m_PrivateKey);
                    byte[] aPrivateKeyData = privateKeyInfo.ToAsn1Object().GetDerEncoded();
                    strPrvHex = aPrivateKeyData.ToHexString();
                    if (strPrvHex == null)
                        return false;

                    //File.WriteAllBytes(strFilename+".der", aPrivateKeyData);
                }

                {
                    //m_PublicKey to byte[]
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(m_PublicKey);
                    byte[] aPublicKeyData = publicKeyInfo.ToAsn1Object().GetDerEncoded();
                    strPubHex = aPublicKeyData.ToHexString();
                    if (strPubHex == null)
                        return false;
                }

                string[] astrLines = { strPrvHex, strPubHex };

                File.WriteAllLines(strFilename, astrLines);
                if (File.Exists(strFilename) == false)
                {
                    strFilename.TraceError("Error writing key file: ");
                    return false;
                }

                return true;
            }
            catch (Exception e) { e.CatchMessage().TraceError(); }
            return false;
        }

        public bool LoadFromFile(string strFilename)
        {
            try
            {
                string[] astrLines = File.ReadAllLines(strFilename);
                if (astrLines.Length != 2)
                    return false;

                RsaKeyParameters rsaPrvKey, rsaPubKey;

                //Convert Private
                {
                    byte[] aData = astrLines[0].ToByteArray();

                    if ((aData == null) || (aData.Length == 0))
                        return false;

                    rsaPrvKey = (RsaKeyParameters)PrivateKeyFactory.CreateKey(aData);
                    if (rsaPrvKey == null)
                        return false;
                }

                //Convert Public
                {
                    byte[] aData = astrLines[1].ToByteArray();

                    if ((aData == null) || (aData.Length == 0))
                        return false;

                    rsaPubKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(aData);
                    if (rsaPubKey == null)
                        return false;
                }

                m_PrivateKey = rsaPrvKey;
                m_PublicKey = rsaPubKey;
                return true;
            }
            catch (Exception e) { e.CatchMessage().TraceError(); }
            return false;
        }

        public static bool AESEncryptString(ref string strData, byte[] aAESKey, byte[] aIV = null)
        {
            if (string.IsNullOrEmpty(strData) || (aAESKey.Length != 32))
                return false;

            // Convert the string into a byte array
            byte[] aData = Encoding.UTF8.GetBytes(strData);

            if (false == AESEncryptArray(ref aData, aAESKey, aIV))
                return false;

            // Convert the encrypted byte array and IV to a hex string
            strData = aData.ToHexString();

            return true;
        } //AESEncryptString

        //IN:  aData = clear data.
        //OUT: aData = Encrypted data + 16 byte IV
        public static bool AESEncryptArray(ref byte[] aData, byte[] aAESKey, byte[] aIV = null)
        {
            return AESEncDecArray(true, ref aData, aAESKey, aIV);
        } // EncryptArray

        public static bool AESDecryptString(ref string strData, byte[] aAESKey)
        {
            if (string.IsNullOrEmpty(strData) || (aAESKey.Length != 32))
                return false;

            // Convert the string into a byte array
            byte[] aData = strData.ToByteArray();

            if (false == AESDecryptArray(ref aData, aAESKey))
                return false;

            // Convert the decrypted byte array to string
            strData = Encoding.UTF8.GetString(aData, 0, aData.Length);

            return strData.Length > 0;
        } //DecryptString

        //IN:  aData = Encrypted data + 16 byte IV
        //OUT: aData = Decrypted data
        public static bool AESDecryptArray(ref byte [] aData, byte[] aAESKey)
        {
            return AESEncDecArray(false, ref aData, aAESKey, null);
        } // DecryptArray

        /*
        private static bool DONT_USE_AESEncDecArray(bool bEncryptorDecrypt, ref byte[] aData, byte[] aAESKey, byte[] aIV = null)
        {
            bool bRet = true;
            try
            {
                if (   (aData == null)
                    || ((bEncryptorDecrypt == true)  && (aData.Length == 0))
                    || ((bEncryptorDecrypt == false) && (aData.Length <= 16))   //Must be longer than the IV, when decrypting
                    || (aAESKey.Length != 32)
                    || ((aIV != null) && (aIV.Length != 16)))
                    return false;

                // Instantiate a new Aes object to perform string symmetric encryption

                using (Rijndael AES = RijndaelManaged.Create())  //Not FIPS compliant.  :(
                //using (Aes AES = Aes.Create())  //Issues! Not compatible with AES CPP implementation
                {
                    //Construct the IV
                    bool bIVWasNull = (aIV == null);
                    if (bIVWasNull)
                        aIV = new byte[16];

                    if (bEncryptorDecrypt)
                    {
                        if (bIVWasNull)
                            aIV.FillRandom();  //when encrypting: new IV
                    }
                    else
                        Array.Copy(aData, aData.Length - 16, aIV, 0, 16);  //when decrypting: use the IV thats the last 16 bytes of the data.

                    // Set mode, padding, key and IV
                    AES.Mode      = CipherMode.CFB;
                    AES.Padding   = PaddingMode.None;
                    AES.Key       = aAESKey;
                    AES.IV        = aIV;
                    AES.BlockSize = 128; //16 bytes

                    // Instantiate a new MemoryStream object to contain the encrypted bytes
                    MemoryStream ms = new MemoryStream();
                    //Dispose not required on MemoryStream, but gives a compiler warning/error when in a 'using' as CryptoStream below disposes of it as well.
                    //using (MemoryStream ms = new MemoryStream())
                    {
                        // Instantiate a new encryptor/decryptor from our Aes object
                        using (ICryptoTransform aesCryptor = bEncryptorDecrypt ? AES.CreateEncryptor() : AES.CreateDecryptor())
                        {
                            // Instantiate a new CryptoStream object to process the data and write it to the memory stream
                            using (CryptoStream cs = new CryptoStream(ms, aesCryptor, CryptoStreamMode.Write))
                            {
                                // Encrypt/decrypt the input
                                int iCount = bEncryptorDecrypt ? aData.Length : aData.Length - 16;
                                cs.Write(aData, 0, iCount);  //-16, ignore the IV

                                //Add padding
                                int iPadded = -1;
                                {
                                    //Padding.. .Why do we have to do this!
                                    int iBlockSizeInBytes = AES.BlockSize / 8;  //Bits to bytes.

                                    int iCompleteBlock = iBlockSizeInBytes - (iCount % iBlockSizeInBytes);
                                    if (iCompleteBlock < iBlockSizeInBytes)
                                    {
                                        iPadded = iCompleteBlock;
                                        byte[] aZero = new byte[iPadded];
                                        cs.Write(aZero, 0, iPadded);  //-16, ignore the IV
                                    }

                                }

                                // Complete the encrypt/decrypt process
                                cs.FlushFinalBlock();

                                //Remove Padding
                                if (iPadded > 0)
                                {

                                    long iLen = ms.Length;
                                    if (iLen > iPadded)
                                        ms.SetLength(iLen - iPadded);
                                }

                                if (bEncryptorDecrypt)
                                    ms.Write(aIV, 0, aIV.Length);

                                // Convert the encrypted/decrypted data from a MemoryStream to a byte array
                                aData = ms.ToArray();
                            }
                        }
                    }
                }
            }
            catch (Exception e) { bRet = false;  e.CatchMessage().TraceError("EncDecArray(): "); }
            return bRet;
        } // DONT_USE_AESEncDecArray
        */

        private static bool AESEncDecArray(bool bEncryptorDecrypt, ref byte[] aData, byte[] aAESKey, byte[] aIV = null)
        {
            bool bRet = true;
            try
            {
                if (    (aData == null)
                    || ((bEncryptorDecrypt == true)  && (aData.Length == 0))
                    || ((bEncryptorDecrypt == false) && (aData.Length <= 16))   //Must be longer than the IV, when decrypting
                    || (aAESKey.Length != 32)
                    || ((aIV != null) && (aIV.Length != 16)))
                    return false;

                //Construct the IV
                bool bIVWasNull = (aIV == null);
                if (bIVWasNull)
                    aIV = new byte[16];

                int iDataLength = 0;
                if (bEncryptorDecrypt)
                {
                    iDataLength = aData.Length;
                    if (bIVWasNull)
                        aIV.FillRandom();  //when encrypting: new IV
                }
                else
                {
                    Array.Copy(aData, aData.Length - 16, aIV, 0, 16);  //when decrypting: use the IV thats the last 16 bytes of the data.
                    iDataLength = aData.Length - 16;
                }

                CfbBlockCipher cfb = new CfbBlockCipher(new AesEngine(), 128);
                cfb.Init(bEncryptorDecrypt, new ParametersWithIV(new KeyParameter(aAESKey), aIV));

                int iBlockSize = cfb.GetBlockSize();
                for (int i = 0; i < iDataLength; i += iBlockSize)
                {
                    int iRet = 0;
                    int iRemaining = iDataLength - i;
                    if (iRemaining < iBlockSize)
                    {
                        //Last partial block
                        byte[] aIn = new byte[iBlockSize];
                        byte[] aOut = new byte[iBlockSize];
                        Array.Copy(aData, i, aIn, 0, iRemaining);

                        if (bEncryptorDecrypt)
                            iRet = cfb.EncryptBlock(aIn, 0, aOut, 0);
                        else
                            iRet = cfb.DecryptBlock(aIn, 0, aOut, 0);
                        Array.Copy(aOut, 0, aData, i, iRemaining);
                        continue;
                    }

                    if (bEncryptorDecrypt)
                        iRet = cfb.EncryptBlock(aData, i, aData, i);
                    else
                        iRet = cfb.DecryptBlock(aData, i, aData, i);
                }

                if (bEncryptorDecrypt)
                {
                    //Append IV.
                    Array.Resize(ref aData, iDataLength + 16);
                    Array.Copy(aIV, 0, aData, iDataLength, 16);
                }
                else
                {
                    //Remove IV
                    Array.Resize(ref aData, iDataLength);
                }

            }
            catch (Exception e) { bRet = false; e.CatchMessage().TraceError("AESEncDecArray(): "); }
            return bRet;
        } // AESEncDecArray
    } // class CipheriseBouncyCastle

    internal static class BouncyCastleHelpers
    {
        //BouncyCastle Signer
        public static bool SignHexString(this AsymmetricKeyParameter PrivateKey, string strHexedData, out string strHexedSignature)
        {
            try
            {
                byte[] msgBytes = strHexedData.ToByteArray();

                ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
                signer.Init(true, PrivateKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                byte[] sigBytes = signer.GenerateSignature();

                strHexedSignature = sigBytes.ToHexString();
                return true;
            }
            catch (Exception e) { e.CatchMessage().TraceError("SignHexString(): "); }
            strHexedSignature = null;
            return false;
        }

        public static bool VerifyHexString(this AsymmetricKeyParameter PublicKey, string strHexedData, string strHexedSignature)
        {
            try
            {
                byte[] msgBytes = strHexedData.ToByteArray();
                byte[] sigBytes = strHexedSignature.ToByteArray();

                ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
                signer.Init(false, PublicKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);

                return signer.VerifySignature(sigBytes);
            }
            catch (Exception e) { e.CatchMessage().TraceError("SignHexString(): "); }
            return false;
        }

        public static bool EncryptBuffer(this AsymmetricKeyParameter PublicKey, byte[] aClearData, out string strHexedEncrypted)
        {
            strHexedEncrypted = null;
            try
            {
                var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                encryptEngine.Init(true, PublicKey);
                strHexedEncrypted = encryptEngine.ProcessBlock(aClearData, 0, aClearData.Length).ToHexString();

                return strHexedEncrypted.Length > 0;
            }
            catch (Exception e) { e.CatchMessage().TraceError("EncryptBuffer(): "); }
            return false;
        }

        public static bool DecryptBuffer(this AsymmetricKeyParameter PrivateKey, string strHexedEncrypted, out byte[] aData)
        {
            aData = null;
            try
            {
                byte[] aEncryptedData = strHexedEncrypted.ToByteArray();
                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, PrivateKey);

                aData = decryptEngine.ProcessBlock(aEncryptedData, 0, aEncryptedData.Length);

                return aData.Length > 0;
            }
            catch (Exception e) { e.CatchMessage().TraceError("DecryptBuffer(): "); }
            return false;
        }

        public static bool ToPem(this AsymmetricKeyParameter Key, out string strPEM)
        {
            try
            {
                TextWriter textWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(textWriter);

                pemWriter.WriteObject(Key);
                pemWriter.Writer.Flush();
                strPEM = textWriter.ToString();
                return true;
            }
            catch (Exception e) { e.CatchMessage().TraceError("ToPem(): "); }
            strPEM = null;
            return false;
        }

        //T == RsaKeyParameters, RsaPrivateCrtKeyParameters, AsymmetricKeyParameter, AsymmetricCipherKeyPair
        public static bool FromPem<T>(this string strPEM, out T Key)
        {
            Key = default(T);
            try
            {
                using (StringReader reader = new StringReader(strPEM))
                {
                    PemReader pemReader = new PemReader(reader);

                    object o = pemReader.ReadObject();
                    if ((o is T) == false)
                        return false;

                    Key = (T)o;
                    return true;
                }
            }
            catch (Exception e) { e.CatchMessage().TraceError("FromPem(): "); }
            return false;
        }

    } // class BouncyCastleHelpers

    internal class CryptoApiRandomGenerator : IRandomGenerator
    {
        private readonly RandomNumberGenerator rndProv;

        public CryptoApiRandomGenerator() : this(new RNGCryptoServiceProvider())
        {
        }

        public CryptoApiRandomGenerator(RandomNumberGenerator rng)
        {
            this.rndProv = rng;
        }

        public virtual void AddSeedMaterial(byte[] seed)
        {
        }

        public virtual void AddSeedMaterial(long seed)
        {
        }

        public virtual void NextBytes(byte[] bytes)
        {
            this.rndProv.GetBytes(bytes);
        }

        public virtual void NextBytes(byte[] bytes, int start, int len)
        {
            if (start < 0)
            {
                throw new ArgumentException("Start offset cannot be negative", "start");
            }
            if ((int)bytes.Length < start + len)
            {
                throw new ArgumentException("Byte array too small for requested offset and length");
            }
            if ((int)bytes.Length == len && start == 0)
            {
                this.NextBytes(bytes);
                return;
            }
            byte[] numArray = new byte[len];
            this.NextBytes(numArray);
            Array.Copy(numArray, 0, bytes, start, len);
        }
    }

} //namespace Cipherise.Common
#endif