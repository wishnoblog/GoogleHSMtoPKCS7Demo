using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GoogleHSMtoPKCS7Demo
{
    internal class Program
    {
        private static readonly string _projectId = ".....";
        private static readonly string _locationId = "....";
        private static readonly string _keyRingId = "....";
        private static readonly string _keyId = "....";
        private static readonly string _cerPath = @"C:\....\.....cer";
        static void Main(string[] args)
        {

            string message = @"產生PKCS1TEST 測試訊息 這是測試資料";


            Console.WriteLine("取得GOOGLE_APPLICATION_CREDENTIALS");
            string credentialPath = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");
            Console.WriteLine($"GOOGLE_APPLICATION_CREDENTIALS: {credentialPath}");
           

            #region 產生PKCS1
            //呼叫範例
            byte[] data = Encoding.UTF8.GetBytes(message);
            byte[] signature = Pkcs1Helper.SignDataWithPKCS1(_projectId, _locationId, _keyRingId, _keyId, "1", data);
            //base64
            string signatureBase64 = Convert.ToBase64String(signature);
            Console.WriteLine($"PKCS#1 :{signatureBase64}");

            Console.WriteLine("測試驗證PKCS#1 ");
            var result = Pkcs1Helper.VerifySignature(_projectId, _locationId, _keyRingId, _keyId, "1", data, signature);
            Console.WriteLine($"驗證結果 :{result}");
            #endregion

            #region DEBUG HSM
            var x509v2 = LoadCerHelper.LoadCertificateFromPossiblyBase64Cer(_cerPath);
            Console.WriteLine("憑證主體： " + x509v2.Subject);
            VerifyPkcsHelper.VerifyPkcs1Signature(data, signature, x509v2);
            #endregion

            #region 產生PKCS7 無Attributes
            Console.WriteLine($"-----------------pkcs7-----------");

            // 轉為 BouncyCastle 的 X509Certificate
            Org.BouncyCastle.X509.X509CertificateParser parser = new Org.BouncyCastle.X509.X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate x509Certificate = parser.ReadCertificate(x509v2.RawData);
            byte[] pkcs7Bytes = Pkcs7HelperV2.CreatePkcs7FromPkcs1(data, signature, x509Certificate);
            string pkcs7Base64 = Convert.ToBase64String(pkcs7Bytes);
            VerifyPkcsHelper.VerifyPkcs7(pkcs7Bytes, data);
            #endregion

            #region 產生PKCS7 有Attributes
            Console.WriteLine($"-----------------pkcs7 With Attributes-----------");


            // 你的 HSM 簽章函數（簽 SHA256 雜湊）
            static byte[] signHashFunc(byte[] hash) =>
                Pkcs1Helper.SignHashWithPKCS1(_projectId, _locationId, _keyRingId, _keyId, "1", hash, HashAlgorithmName.SHA256);

            byte[] pkcs7WithAttrs = Pkcs7HelperV2.GeneratePkcs7WithSignedAttributesFromHsm(data, x509Certificate, signHashFunc);

            // 檢查
            VerifyPkcsHelper.VerifyPkcs7WithAttributes(pkcs7WithAttrs, data);
            #endregion
        }
    }
}
