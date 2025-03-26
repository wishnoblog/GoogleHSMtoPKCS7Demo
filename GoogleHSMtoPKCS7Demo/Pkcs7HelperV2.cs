using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace GoogleHSMtoPKCS7Demo
{
    public static class Pkcs7HelperV2
    {
        /// <summary>
        /// 使用 BouncyCastle 建立 PKCS#7 Detached 簽章 (不含 SignedAttributes)
        /// </summary>
        public static byte[] CreatePkcs7FromPkcs1(byte[] data, byte[] pkcs1Signature, X509Certificate signerCert)
        {
            // 1. 定義演算法 OID
            var oidData = new DerObjectIdentifier("1.2.840.113549.1.7.1"); // data
            var oidSignedData = new DerObjectIdentifier("1.2.840.113549.1.7.2"); // signedData
            var oidSha256 = new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
            var oidRsaSha256 = new DerObjectIdentifier("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption

            var digestAlgId = new AlgorithmIdentifier(oidSha256, DerNull.Instance);
            var sigAlgId = new AlgorithmIdentifier(oidRsaSha256, DerNull.Instance);

            // 2. 建立 SignerIdentifier（Issuer + SerialNumber）
            var issuerAndSerial = new IssuerAndSerialNumber(signerCert.IssuerDN, signerCert.SerialNumber);
            var signerIdentifier = new SignerIdentifier(issuerAndSerial);

            // 3. 組成 SignerInfo
            var signerInfoVector = new Asn1EncodableVector
            {
                new DerInteger(1), // version
                signerIdentifier.ToAsn1Object(),
                digestAlgId,
                sigAlgId,
                new DerOctetString(pkcs1Signature)
            };
            var signerInfo = new DerSequence(signerInfoVector);

            // 4. digestAlgorithms SET
            var digestAlgs = new DerSet(digestAlgId);

            // 5. contentInfo (detached 模式 content=null)
            var contentInfo = new ContentInfo(oidData, null);

            // 6. 包裝簽章憑證
            var certVector = new Asn1EncodableVector { signerCert.CertificateStructure };
            var certSet = new DerSet(certVector);
            var certTagged = new DerTaggedObject(false, 0, certSet); // [0] IMPLICIT CertificateSet

            // 7. SignerInfos SET
            var signerInfos = new DerSet(signerInfo);

            // 8. 組成 SignedData
            var signedDataVector = new Asn1EncodableVector
            {
                new DerInteger(3), // version
                digestAlgs,
                contentInfo,
                certTagged,
                signerInfos
            };
            var signedData = new DerSequence(signedDataVector);

            // 9. 組成 ContentInfo (封裝 signedData)
            var finalContentInfo = new ContentInfo(oidSignedData, signedData);

            // 10. DER 編碼後回傳
            return finalContentInfo.GetEncoded();
        }




        /// <summary>
        /// 自動產生 SignedAttributes、透過 HSM 簽章並組成帶 Attributes 的 PKCS#7 簽章
        /// </summary>
        /// <param name="data">原始資料</param>
        /// <param name="signerCert">簽章者憑證（BouncyCastle X509）</param>
        /// <param name="signHashFunc">Func 傳入 hash，回傳 HSM 簽章 byte[]</param>
        /// <returns>PKCS#7 (CMS SignedData with SignedAttributes)</returns>
        public static byte[] GeneratePkcs7WithSignedAttributesFromHsm(
        byte[] data,
        X509Certificate signerCert,
        Func<byte[], byte[]> signHashFunc)
        {
            var oidData = new DerObjectIdentifier("1.2.840.113549.1.7.1");       // data
            var oidSignedData = new DerObjectIdentifier("1.2.840.113549.1.7.2"); // signedData
            var oidSha256 = new DerObjectIdentifier("2.16.840.1.101.3.4.2.1");   // sha256
            var oidRsaSha256 = new DerObjectIdentifier("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption

            var digestAlgId = new AlgorithmIdentifier(oidSha256, DerNull.Instance);
            var sigAlgId = new AlgorithmIdentifier(oidRsaSha256, DerNull.Instance);

            // === 1. 組 SignedAttributes ===
            var attrVector = new Asn1EncodableVector();

            // contentType
            attrVector.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(
                new DerObjectIdentifier("1.2.840.113549.1.9.3"),
                new DerSet(oidData)));

            // messageDigest
            byte[] hashOfData = DigestUtilities.CalculateDigest("SHA-256", data);
            attrVector.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(
                new DerObjectIdentifier("1.2.840.113549.1.9.4"),
                new DerSet(new DerOctetString(hashOfData))));

            var signedAttributes = new DerSet(attrVector);
            byte[] signedAttrBytes = signedAttributes.GetEncoded();

            // === 2. HSM 簽章：直接傳入 DER 編碼的 SignedAttributes
            byte[] pkcs1Signature = signHashFunc(signedAttrBytes);

            // === 3. SignerInfo ===
            var issuerAndSerial = new IssuerAndSerialNumber(signerCert.IssuerDN, signerCert.SerialNumber);
            var signerIdentifier = new SignerIdentifier(issuerAndSerial);

            var signerInfo = new DerSequence(new Asn1Encodable[]
            {
            new DerInteger(3),
            signerIdentifier.ToAsn1Object(),
            digestAlgId,
            new DerTaggedObject(false, 0, signedAttributes),
            sigAlgId,
            new DerOctetString(pkcs1Signature)
            });

            // === 4. SignedData ===
            var digestAlgs = new DerSet(digestAlgId);
            var contentInfo = new ContentInfo(oidData, null);

            var certVector = new Asn1EncodableVector { signerCert.CertificateStructure };
            var certSet = new DerSet(certVector);
            var certTagged = new DerTaggedObject(false, 0, certSet);

            var signerInfos = new DerSet(signerInfo);

            var signedData = new DerSequence(new Asn1Encodable[]
            {
            new DerInteger(3),
            digestAlgs,
            contentInfo,
            certTagged,
            signerInfos
            });

            var finalContentInfo = new ContentInfo(oidSignedData, signedData);
            return finalContentInfo.GetEncoded();
        }
    }
}
