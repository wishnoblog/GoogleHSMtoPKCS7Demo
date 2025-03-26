using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace GoogleHSMtoPKCS7Demo
{
    public class VerifyPkcsHelper
    {
        /// <summary>
        /// 驗證 PKCS#7（CMS SignedData）簽章，包含 SignedAttributes 驗證
        /// </summary>
        /// <param name="pkcs7">PKCS#7 簽章資料（含簽章與憑證）</param>
        /// <param name="originalData">原始資料（被簽的內容）</param>
        public static bool VerifyPkcs7WithAttributes(byte[] pkcs7, byte[] originalData)
        {
            try
            {
                var contentInfo = new ContentInfo(originalData);
                var signedCms = new SignedCms(contentInfo, detached: true);
                signedCms.Decode(pkcs7);

                // true = 嚴格驗證 signed attributes（如 messageDigest, contentType）
                signedCms.CheckSignature(true);

                Console.WriteLine("簽章驗證成功（含 SignedAttributes）");
                return true;
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("簽章驗證失敗（含 SignedAttributes）：" + ex.Message);
                return false;
            }
        }


        /// <summary>
        /// 驗證 HSM 簽出的 PKCS#1 簽章
        /// </summary>
        public static bool VerifyPkcs1Signature(byte[] data, byte[] signature, X509Certificate2 cert)
        {
            using RSA? rsa = cert.GetRSAPublicKey();
            if (rsa == null)
            {
                Console.WriteLine("無法從憑證取得 RSA 公鑰");
                return false;
            }

            bool result = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.WriteLine(result ? "驗章成功！" : "驗章失敗！");
            return result;
        }

        /// <summary>
        /// 驗證 PKCS#7 簽章 不含Attributes
        /// </summary>
        /// <param name="pkcs7Data"></param>
        /// <param name="originalData"></param>
        /// <returns></returns>
        public static bool VerifyPkcs7(byte[] pkcs7Data, byte[] originalData)
        {
            try
            {
                var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(originalData);
                var signedCms = new System.Security.Cryptography.Pkcs.SignedCms(contentInfo, detached: true);
                signedCms.Decode(pkcs7Data);
                signedCms.CheckSignature(true);
                Console.WriteLine("PKCS#7 簽章驗證成功！");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PKCS#7 驗證失敗: {ex.Message}");
                return false;
            }
        }
    }
}
