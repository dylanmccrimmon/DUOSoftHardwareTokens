<#PSScriptInfo

.VERSION 1.0

.GUID 85d097f4-3d7b-4e00-a426-b3a7eac0732e

.AUTHOR Dylan McCrimmon

.COMPANYNAME 

.COPYRIGHT 

.TAGS 

.LICENSEURI 

.PROJECTURI https://github.com/dylanmccrimmon/DUOSoftHardwareTokens

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
#>

Param(
    [parameter()]
    [switch] $ShowLog,

    [parameter()]
    [int] $Period = 30,

    [parameter()]
    [ValidateSet(6, 8)]
    [int] $Digits = 6
)

Function New-SerialNumber() {
    $RandomNumber = Get-Random -Minimum -10000000 -Maximum 99999999
    return "998" + $RandomNumber
}

Function New-Seed() {
    $RNG = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
    [Byte[]]$x=1
    for($r=''; $r.length -lt 32){$RNG.GetBytes($x); if([char]$x[0] -clike '[2-7A-Z]'){$r+=[char]$x[0]}}
    return $r
}

Function Convert-IntToHex([int]$num) {
    return ('{0:x}' -f $num)
}

Function Add-LeftPad($str, $len, $pad) {
    if(($len + 1) -ge $str.Length) {
        while (($len - 1) -ge $str.Length) {
            $str = ($pad + $str)
        }
    }
    return $str;
}

Function Convert-Base32ToHex($base32) {
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    $hex = "";
    for ($i = 0; $i -lt $base32.Length; $i++) {
        $val = $base32chars.IndexOf($base32.Chars($i));
        $binary = [Convert]::ToString($val, 2)
        $staticLen = 5
        $padder = '0'
            # Write-Host $binary
        $bits += Add-LeftPad $binary.ToString()  $staticLen  $padder
    }

    for ($i = 0; $i+4 -le $bits.Length; $i+=4) {
        $chunk = $bits.Substring($i, 4)
        # Write-Host $chunk
        $intChunk = [Convert]::ToInt32($chunk, 2)
        $hexChunk = Convert-IntToHex($intChunk)
        # Write-Host $hexChunk
        $hex = $hex + $hexChunk
    }
    return $hex;
}

Function Write-Log ($Message, $Severity = "INFO") {
    if ($ShowLog) {
        Write-Output "[$(Get-Date -Format "o")] [$($Severity)] $Message"
    }
}

Write-Log "Generating Serial Number"
$SerialNumber = New-SerialNumber
Write-Log "Serial Number has been created"

Write-Log "Generating Seed Number"
$Seed = New-Seed
Write-Log "Seed has been created"

Write-Log "Convering Hex from seed"
$Hex = (Convert-Base32ToHex($Seed)).ToUpper()
Write-Log "Conversion complete"


$TOTPQRCodeData = "otpauth://totp/DUOHardwareToken($($SerialNumber))?secret=$($Seed)&algorithm=SHA1&digits=$($Digits)&period=$($Period)"
$DUOCSVData = "$($SerialNumber),$($Hex),$($Period)"

Write-Log "Duo CSV token data: $DUOCSVData"
Write-Log "QR Code Data: $TOTPQRCodeData"

return [PSCustomObject]@{
    SerialNumber    = $SerialNumber
    TOTPSecret      = $Seed
    TOTPSecretKey   = $Hex
    TOTPApplication = [PSCustomObject]@{
        Secret = $Seed
        Algorithm = 'SHA1'
        Digits = $Digits
        Period = $Period
    }
    DUOCSVData      = $DUOCSVData
    TOTPQRCodeData  = $TOTPQRCodeData
}