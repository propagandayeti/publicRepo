#Test for TLS 1.0 and TLS 1.1 disabled with TLS 1.2 enabled
$ErrorActionPreference="Continue"
$VerbosePreference="Continue"

#Verify TLS 1.0/1.1 disabled and 1.2 enabled
$TLS1MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
$TLS11MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
$TLS12MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
$ESCipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
$NET_WOW6432NodeMainKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
$NET_64MainKey = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"

#Verify TLS 1.0/1.1 disabled and 1.2 enabled
$TLS10=Get-ItemProperty "$TLS1MainKey\Client" -Name Enabled
$TLS11=Get-ItemProperty "$TLS11MainKey\Client" -Name Enabled
$TLS12=Get-ItemProperty "$TLS12MainKey\Client" -Name Enabled
$NET_WOW6432=Get-ItemProperty -Path $NET_WOW6432NodeMainKey -Name SystemDefaultTlsVersions
$NET_64=Get-ItemProperty -Path $NET_64MainKey -Name SystemDefaultTlsVersions
$3DES=Get-ItemProperty "$ESCipherRootKey\Triple DES 168" -Name Enabled

if(($TLS10.Enabled -ne 0) -or ($TLS11.Enabled -ne 0) -or ($TLS12.Enabled -ne 1) -or ($NET_WOW6432.SystemDefaultTlsVersions -ne 1) -or ($NET_64.SystemDefaultTlsVersions -ne 1)){ 
    Write-Host "Error. TLS1.0 should be 0 but is (" $TLS10.Enabled ") and TLS1.1 should be 0 but is ("$TLS11.Enabled ") and TLS 1.2 should be 1 but is (" $TLS12.Enabled "). NETApps [32|64]("$NET_WOW6432.SystemDefaultTlsVersions " | " $NET_64.SystemDefaultTlsVersions ")"
    #issue
    exit 1
}
elseif ($3DES.Enabled -ne 0){
    Write-Host "3DES not disabled (SWEET32 vuln)"
    exit 1
}
else{
    #no issue
    Write-Host "All is well. TLS1.0 should be 0 (" $TLS10.Enabled ") and TLS1.1 should be 0 ("$TLS11.Enabled ") and TLS 1.2 should be 1 (" $TLS12.Enabled "). 3DES should be 0 ("$3DES.Enabled") NETApps [32|64]("$NET_WOW6432.SystemDefaultTlsVersions " | " $NET_64.SystemDefaultTlsVersions ")"
    exit 0
}