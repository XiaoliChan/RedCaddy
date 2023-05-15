add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$headers = @{
    "user-agent" = 'SecurityString'
    "Accept-SecurityString"  = 'REPLACE_SECURITY_STRINGS'      
}
Invoke-WebRequest https://REPLACE_TO_VPS_IP:REPLACE_PORT/REPLACE_WARDEN_PATH -Headers $headers
