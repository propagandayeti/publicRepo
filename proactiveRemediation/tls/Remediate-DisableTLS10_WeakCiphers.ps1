#Sources
#https://www.jorgebernhardt.com/disable-ssl-and-tls-on-winserv/
#https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/

#### Disable RC4 ####
Write-host "Disabling RC4 Ciphers"
$RC4CipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
# $([char]0x2215) in order to have / in name
$Keyname1 = "RC4 56$([char]0x2215)128"
$Keyname2 = "RC4 40$([char]0x2215)128"
$Keyname3 = "RC4 128$([char]0x2215)128"
$Keyname4 = "RC4 64$([char]0x2215)128"
New-Item $RC4CipherRootKey$Keyname1 -Force
New-Item $RC4CipherRootKey$Keyname2 -Force
New-Item $RC4CipherRootKey$Keyname3 -Force
New-Item $RC4CipherRootKey$Keyname4 -Force
Set-ItemProperty $RC4CipherRootKey$Keyname1 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC4CipherRootKey$Keyname2 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC4CipherRootKey$Keyname3 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC4CipherRootKey$Keyname4 -Name Enabled -Value 0 -Type Dword
#### End Disable RC4 ####

#### Disable RC2 ####
Write-host "Disabling RC2 Ciphers"
$RC2CipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
# $([char]0x2215) in order to have / in name
$Keyname1 = "RC2 56$([char]0x2215)128"
$Keyname2 = "RC2 40$([char]0x2215)128"
$Keyname3 = "RC2 128$([char]0x2215)128"
New-Item $RC2CipherRootKey$Keyname1 -Force
New-Item $RC2CipherRootKey$Keyname2 -Force
New-Item $RC2CipherRootKey$Keyname3 -Force
Set-ItemProperty $RC2CipherRootKey$Keyname1 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC2CipherRootKey$Keyname2 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC2CipherRootKey$Keyname3 -Name Enabled -Value 0 -Type Dword
#### End Disable RC2 ####

#### Disable DES and Triple DES ####
Write-host "Disabling Weak DES/3DES Ciphers"
$ESCipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
$Keyname1 = "DES 56$([char]0x2215)56"
$Keyname2 = "Triple DES 168"
New-Item $ESCipherRootKey$Keyname1 -Force
New-Item $ESCipherRootKey$Keyname2 -Force
Set-ItemProperty $ESCipherRootKey$Keyname1 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $ESCipherRootKey$Keyname2 -Name Enabled -Value 0 -Type Dword
#### End DES and Triple DES ####

#### Disable SSL3.0 ####
write-host "Disabling SSL3.0 protocol"
$SSL3MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"

New-Item "$SSL3MainKey\Client\" -Force
Set-ItemProperty "$SSL3MainKey\Client\" -Name "DisabledByDefault" -Value 1 -Type Dword

New-Item "$SSL3MainKey\Server\" -Force
Set-ItemProperty "$SSL3MainKey\Server\" -Name "Enabled" -Value 0 -Type Dword
#### End Disable SSL3.0 ####

#### Disable SSL2.0 ####
write-host "Disabling SSL2.0 protocol"
$SSL2MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"

New-Item "$SSL2MainKey\Client\" -Force
Set-ItemProperty "$SSL2MainKey\Client\" -Name "DisabledByDefault" -Value 1 -Type Dword

New-Item "$SSL2MainKey\Server\" -Force
Set-ItemProperty "$SSL2MainKey\Server\" -Name "Enabled" -Value 0 -Type Dword
#### End Disable SSL2.0 ####

#Enable TLS 1.2
$TLS12MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
New-Item "$TLS12MainKey\Server" -Force | Out-Null
New-ItemProperty -path "$TLS12MainKey\Server" -name "Enabled" -value "1" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS12MainKey\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force
New-Item "$TLS12MainKey\Client" -Force | Out-Null
New-ItemProperty -path "$TLS12MainKey\Client" -name "Enabled" -value "1" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS12MainKey\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force
Write-Host "TLS 1.2 has been enabled."

#Disable TLS 1.0
$TLS10MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
New-Item "$TLS10MainKey\Server" -Force
New-ItemProperty -path "$TLS10MainKey\Server\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS10MainKey\Server\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
New-Item "$TLS10MainKey\Client\" -Force
New-ItemProperty -path "$TLS10MainKey\Client\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS10MainKey\Client\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
Write-Host "TLS 1.0 has been disabled."

#Disable TLS 1.1
$TLS11MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
New-Item "$TLS11MainKey\Server" -Force
New-ItemProperty -path "$TLS11MainKey\Server\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS11MainKey\Server\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
New-Item "$TLS11MainKey\Client\" -Force
New-ItemProperty -path "$TLS11MainKey\Client\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS11MainKey\Client\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
Write-Host "TLS 1.1 has been disabled."

#Force TLS 1.2 for .NET apps
$NET_WOW6432NodeMainKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
$NET_64MainKey = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
New-ItemProperty -path $NET_WOW6432NodeMainKey -name SystemDefaultTlsVersions -value 1 -PropertyType DWORD
New-ItemProperty -path $NET_WOW6432NodeMainKey -name SchUseStrongCrypto -value 1 -PropertyType DWORD
New-ItemProperty -path $NET_64MainKey -name SystemDefaultTlsVersions -value 1 -PropertyType DWORD
New-ItemProperty -path $NET_64MainKey -name SchUseStrongCrypto -value 1 -PropertyType DWORD

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