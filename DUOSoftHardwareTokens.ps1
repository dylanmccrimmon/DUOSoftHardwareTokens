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
    [string] $DUOAPIHostName,

    [parameter()]
    [string] $DUOAPIIntegrationKey,

    [parameter()]
    [string] $DUOAPISecretKey,

    [parameter()]
    [ValidateSet(30, 60)]
    [Int16] $TOTPPeriod = 30,

    [parameter()]
    [ValidateSet(6, 8)]
    [Int16] $TOTPDigits = 6,

    [parameter()]
    [switch] $OutputTOTPData,

    [parameter()]
    [switch] $SkipTOTPUserVerification,

    [parameter()]
    [switch] $SkipTOTPQRCodeLink
)

Function New-SerialNumber() {
    $RandomNumber = Get-Random -Minimum 10000000 -Maximum 99999999
    return "999-" + $RandomNumber
}

Function New-Secret() {
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

Function New-DuoRequest(){
    param(
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            $apiHost,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiEndpoint,
        
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            $apiKey,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiSecret,
        
        [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $requestMethod = 'GET',
        
        [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            [System.Collections.Hashtable]$requestParams
    )
    $date = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss -0000")
    $formattedParams = ($requestParams.Keys | Sort-Object | ForEach-Object {$_ + "=" + [uri]::EscapeDataString($requestParams.$_)}) -join "&"
    
    #DUO Params formatted and stored as bytes with StringAPIParams
    $requestToSign = (@(
        $Date.Trim(),
        $requestMethod.ToUpper().Trim(),
        $apiHost.ToLower().Trim(),
        $apiEndpoint.Trim(),
        $formattedParams
    ).trim() -join "`n").ToCharArray().ToByte([System.IFormatProvider]$UTF8)
 
    $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($apiSecret.ToCharArray().ToByte([System.IFormatProvider]$UTF8))
    $hmacsha1.ComputeHash($requestToSign) | Out-Null
    $authSignature = [System.BitConverter]::ToString($hmacsha1.Hash).Replace("-", "").ToLower()

    $authHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f $apiKey, $authSignature)))

    $httpRequest = @{
        URI         = ('https://{0}{1}' -f $apiHost, $apiEndpoint)
        Headers     = @{
            "X-Duo-Date"    = $Date
            "Authorization" = "Basic $authHeader"
        }
        Body = $requestParams
        Method      = $requestMethod
        ContentType = 'application/x-www-form-urlencoded'
    }
    
    $httpRequest
}

Function Get-Otp($Secret, $Digits, $Period){
    $enc = [System.Text.Encoding]::UTF8
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = Convert-HexToByteArray(Convert-Base32ToHex(($Secret.ToUpper())))
    $timeBytes = Get-TimeByteArray $Period
    $randHash = $hmac.ComputeHash($timeBytes)
    
    $offset = $randhash[($randHash.Length-1)] -band 0xf
    $fullOTP = ($randhash[$offset] -band 0x7f) * [math]::pow(2, 24)
    $fullOTP += ($randHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
    $fullOTP += ($randHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
    $fullOTP += ($randHash[$offset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $Digits)
    $otp = $fullOTP % $modNumber
    $otp = $otp.ToString("0" * $Digits)
    return $otp
}

Function Get-TimeByteArray($Period) {
    $span = (New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $unixTime = [Convert]::ToInt64([Math]::Floor($span/$Period))
    $byteArray = [BitConverter]::GetBytes($unixTime)
    [array]::Reverse($byteArray)
    return $byteArray
}

Function Convert-HexToByteArray($hexString) {
    $byteArray = $hexString -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | %{ [Convert]::ToByte( $_, 16 ) }
    return $byteArray
}

Write-Verbose "Generating Serial Number"
$SerialNumber = New-SerialNumber
Write-Verbose "Serial Number has been created"

Write-Verbose "Generating Secret"
$TOTPSecret = New-Secret
Write-Verbose "Secret has been created"

Write-Verbose "Convering Hex from Secret"
$TOTPSecretHex = (Convert-Base32ToHex($TOTPSecret)).ToUpper()
Write-Verbose "Conversion complete"

if (!$SkipTOTPQRCodeLink.IsPresent) {
    Write-Verbose "Constructing QRCode data string"
    $TOTPQRCodeData = "otpauth://totp/DUOHardwareToken($($SerialNumber))?secret=$($TOTPSecret)&issuer=DUOSoftHardwareTokens&algorithm=SHA1&digits=$($TOTPDigits)&period=$($TOTPPeriod)"
    Write-Host "QR Code Link: https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=$TOTPQRCodeData"
}

if ($OutputTOTPData.IsPresent) {
    $TOTPData = [PSCustomObject]@{
        Issuer      = 'DUOHardwareTokens'
        Account     = "DUOHardwareToken($($SerialNumber))"
        Secret      = $TOTPSecret
        Algorithm   = 'HMAC-SHA-1'
        Digits      = $TOTPDigits
        Period      = $TOTPPeriod
    }
    Write-Output $TOTPData
}

## Check TOTP token with the user 
if (!$SkipTOTPUserVerification.IsPresent) {
    Write-Verbose "Starting TOTP user verification"
    $OTPVerified = $false
    do {
        $response = Read-Host -Prompt 'Please enter the TOTP code displayed in your auth app? [OTP or Q to quit]'
        $otp = Get-Otp -Secret $TOTPSecret -Digits $TOTPDigits -Period $TOTPPeriod
        if ($response -eq $otp) {
            Write-Verbose "TOTP verification attempt was successful"
            Write-Host "TOTP is correct. Authenticator application seems to be working correctly"
            $OTPVerified = $true
        } elseif ($response -eq 'Q') {
            Write-Verbose "User requested to quit"
            Write-Verbose "Exiting script"
            exit
        } else {
            Write-Verbose "TOTP verification attempt was unsuccessful"
            Write-Host "TOTP is incorrect. Please try again or check your authentictor app."
        }
    } until ($OTPVerified)
} else {
    Write-Verbose "Skipped TOTP user verification"
}

# Contruct the web request to duo
Write-Verbose "Contructing the web request for Duo"
$values = @{
    apiHost = $DUOAPIHostName
    apiEndpoint     = '/admin/v1/tokens'
    requestMethod   = 'post'
    requestParams   = @{
        type="t$($TOTPDigits)"
        serial=$SerialNumber
        secret=$TOTPSecretHex
        totp_step=$TOTPPeriod
    }
    apiSecret       = $DUOAPISecretKey
    apiKey          = $DUOAPIIntegrationKey
}
$contructWebRequest = New-DuoRequest @values
Write-Verbose "Contructed the web request for Duo"

Write-Verbose "Posting token data to Duo"
$DuoWebRequest = Invoke-WebRequest @contructWebRequest

if ($DuoWebRequest.StatusCode -eq 200) {
    Write-Host "Token data successfully sent to Duo. You can now manage the token in the Duo admin dashboard."
} else {
    Write-Verbose "Token data failed posted to Duo via the API"
    Write-Verbose "Could not import via the API. You can manaully import with the csv data below"
    Write-Host "The script wasn't able to import the hardware token into Duo. You can manually added to token using the data provided below"
    Write-Host "Duo CSV token data: $($SerialNumber),$($TOTPSecretHex),$($TOTPPeriod)"
}