using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Google.Cloud.Kms.V1;
using Google.Protobuf;

namespace GoogleHSMtoPKCS7Demo
{
    public static class Pkcs1Helper
    {
        /// <summary>
        /// 從Google Cloud KMS取得PKCS#1簽章
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="locationId"></param>
        /// <param name="keyRingId"></param>
        /// <param name="keyId"></param>
        /// <param name="keyVersion"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] SignDataWithPKCS1(
            string projectId,
            string locationId,
            string keyRingId,
            string keyId,
            string keyVersion, // 使用第一個金鑰版本
            byte[] data = null)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            // 建立 KMS 用戶端
            KeyManagementServiceClient client = KeyManagementServiceClient.Create();

            // 建立金鑰版本名稱 (非對稱簽章必須指定金鑰版本)
            CryptoKeyVersionName keyVersionName = new CryptoKeyVersionName(projectId, locationId, keyRingId, keyId, keyVersion);

            // 計算資料的 SHA-256 雜湊值
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                // 建立 Digest 物件（如果你使用的簽章演算法與雜湊演算法相符）
                Digest digest = new Digest { Sha256 = ByteString.CopyFrom(hash) };

                // 呼叫 AsymmetricSign API 進行簽章
                AsymmetricSignResponse response = client.AsymmetricSign(keyVersionName, digest);

                // 回傳簽章結果，這就是 PKCS#1 格式的簽章
                return response.Signature.ToByteArray();
            }
        }

        /// <summary>
        /// 取得指定金鑰版本的公鑰，並驗證簽章
        /// </summary>
        /// <param name="projectId">專案ID</param>
        /// <param name="locationId">區域ID</param>
        /// <param name="keyRingId">金鑰環ID</param>
        /// <param name="keyId">金鑰ID</param>
        /// <param name="keyVersion">金鑰版本</param>
        /// <param name="data">原始資料 (byte[])</param>
        /// <param name="signature">由 KMS 產生的 PKCS#1 簽章 (byte[])</param>
        /// <returns>若簽章驗證成功回傳 true，否則 false</returns>
        public static bool VerifySignature(
            string projectId,
            string locationId,
            string keyRingId,
            string keyId,
            string keyVersion,
            byte[] data,
            byte[] signature)
        {
            // 建立 KMS 用戶端
            KeyManagementServiceClient client = KeyManagementServiceClient.Create();

            // 建立金鑰版本名稱
            CryptoKeyVersionName keyVersionName = new CryptoKeyVersionName(projectId, locationId, keyRingId, keyId, keyVersion);

            // 取得公鑰 (PEM 格式)
            var publicKeyResponse = client.GetPublicKey(keyVersionName);
            string publicKeyPem = publicKeyResponse.Pem;
            if (string.IsNullOrEmpty(publicKeyPem))
            {
                throw new Exception("未取得公鑰 PEM 資料");
            }

            // 將 PEM 轉換為 RSA 公鑰
            using (RSA rsa = RSA.Create())
            {
                try
                {
                    // .NET 5 及以上支援 ImportFromPem，將 PEM 轉成 RSA 公鑰
                    rsa.ImportFromPem(publicKeyPem.ToCharArray());
                }
                catch (Exception ex)
                {
                    throw new Exception("轉換公鑰失敗: " + ex.Message);
                }

                // 驗證簽章，假設使用 SHA256 與 PKCS#1 v1.5 padding
                bool isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return isValid;
            }
        }


        /// <summary>
        /// 使用 Google Cloud KMS 簽署 SHA256 雜湊
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="locationId"></param>
        /// <param name="keyRingId"></param>
        /// <param name="keyId"></param>
        /// <param name="keyVersion"></param>
        /// <param name="signedAttributesDer"></param>
        /// <param name="hashAlg"></param>
        /// <returns></returns>
        public static byte[] SignHashWithPKCS1(
            string projectId,
            string locationId,
            string keyRingId,
            string keyId,
            string keyVersion,
            byte[] signedAttributesDer, // <- DER encoded SignedAttributes
            HashAlgorithmName hashAlg)
        {
            // 1. 先計算 SHA256 雜湊（這是你傳給 HSM 的資料）
            byte[] hash = SHA256.HashData(signedAttributesDer);

            // 2. 建立 KMS 用戶端
            var client = KeyManagementServiceClient.Create();

            // 3. 指定要用的 HSM 金鑰版本
            var keyVersionName = new CryptoKeyVersionName(projectId, locationId, keyRingId, keyId, keyVersion);

            // 4. 傳入雜湊值給 Google HSM
            var digest = new Digest
            {
                Sha256 = ByteString.CopyFrom(hash)
            };

            // 5. 呼叫 AsymmetricSign API
            AsymmetricSignResponse response = client.AsymmetricSign(keyVersionName, digest);

            return response.Signature.ToByteArray();
        }
    }
}