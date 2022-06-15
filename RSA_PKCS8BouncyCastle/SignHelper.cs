using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSA_PKCS8BouncyCastle
{
    public class SignHelper
    {
        public Encoding encoding = Encoding.UTF8;
        public string SignerSymbol = "MD5withRSA";
        public void RSASigning() { }
        /// <summary>
        /// 签名模式
        /// </summary>
        /// <param name="e">Encoding</param>
        /// <param name="s">MD5withRSA，SHA256WithRSA</param>
        public void RSASigning(Encoding e, string s)
        {
            encoding = e;
            SignerSymbol = s;
        }
        private AsymmetricKeyParameter CreateKEY(bool isPrivate, string key)
        {
            byte[] keyInfoByte = Convert.FromBase64String(key);
            if (isPrivate)
                return PrivateKeyFactory.CreateKey(keyInfoByte);
            else
                return PublicKeyFactory.CreateKey(keyInfoByte);
        }
        /// <summary> 
        /// 数据加密 
        /// </summary> 
        /// <param name="content">待加密字符串</param>
        /// /// <param name="privatekey">私钥</param> 
        /// <returns>加密后字符串</returns> 
        public string Sign(string content, string privatekey)
        {
            ISigner sig = SignerUtilities.GetSigner(SignerSymbol);
            sig.Init(true, CreateKEY(true, privatekey));

            byte[] bytes = encoding.GetBytes(content); //待加密字符串
            sig.BlockUpdate(bytes, 0, bytes.Length);
            byte[] signature = sig.GenerateSignature(); // Base 64 encode the sig so its 8-bit clean 
            var signedString = Convert.ToBase64String(signature);
            return signedString;
        }

        /// <summary> 
        /// 验证签名 
        /// </summary> 
        /// <param name="content">待签名的字符串</param>
        /// <param name="signData">加密后的文本</param> 
        /// <param name="publickey">公钥文本</param> 
        /// <returns>是否一致</returns> 
        public bool Verify(string content, string signData, string publickey)
        {
            ISigner signer = SignerUtilities.GetSigner(SignerSymbol);
            signer.Init(false, CreateKEY(false, publickey));
            var expectedSig = Convert.FromBase64String(signData);
            var msgBytes = encoding.GetBytes(content);
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            return signer.VerifySignature(expectedSig);
        }
    }
}
