using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GoogleHSMtoPKCS7Demo
{
    public static class LoadCerHelper
    {
        /// <summary>
        /// 萬用憑證載入器，支援 DER、PEM、Base64（無包裝）
        /// </summary>
        public static X509Certificate2 LoadCertificateFromPossiblyBase64Cer(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("找不到憑證檔案", path);

            byte[] raw = File.ReadAllBytes(path);

            // 1. 檢查是否為 PEM 格式
            string text = Encoding.ASCII.GetString(raw);
            if (text.Contains("-----BEGIN CERTIFICATE-----"))
            {
                return new X509Certificate2(raw); // PEM 支援
            }

            // 2. 嘗試將內容視為 Base64 編碼（無包裝）
            try
            {
                string b64 = Encoding.ASCII.GetString(raw)
                    .Replace("\r", "").Replace("\n", "").Trim();

                byte[] der = Convert.FromBase64String(b64);
                return new X509Certificate2(der); // DER 匯入
            }
            catch
            {
                // 3. fallback: 當作原始二進位 DER 嘗試載入
                return new X509Certificate2(raw);
            }
        }
    }
}
