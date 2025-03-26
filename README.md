# GoogleHSMtoPKCS7Demo
Google HSM 產生PKCS簽章 DEMO By WiSH

## 說明：
這是一個簡單的DEMO，用來示範如何使用Google HSM來產生PKCS#1簽章後，轉為PKCS#7簽章。
您需要先申請好Google HSM的服務，並且建立好KeyRing與Key，並且取得好相關的權限。
然後會拿到一個json檔案，裡面包含了您的服務帳戶的私鑰，這個私鑰是用來與Google HSM溝通的。
這個DEMO會示範如何使用這個私鑰來與Google HSM溝通，並且產生PKCS#1簽章，然後轉為PKCS#7簽章。


## 相關說明

- - [我的網誌](https://blog.wishstudio.net/archives/2007)
- [Google HSM 官方文件](https://cloud.google.com/kms/docs/hsm)
- [Google HSM API文件](https://cloud.google.com/kms/docs/reference/rest)
- [Google HSM API Client Libraries](https://cloud.google.com/kms/docs/reference/libraries)
