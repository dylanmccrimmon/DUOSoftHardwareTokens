# DUOSoftHardwareTokens
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

### Overview
DUOSoftHardwareTokens is a script that creates soft hardware tokens (TOTP) for DUO security and imports them to Duo via the Duo Admin API. 

From the script output, you can import the soft hardware tokens (TOTP) into apps such as Google Authenticator and Microsoft Authenticator or into a password database like Keeper.

### Prerequisites
- Duo Admin API details with `Grant write resource` permission.
  - Setup instructions for the Duo Admin API can be [found here](https://duo.com/docs/adminapi).

### Installation / Download
#### Download from Github
``` powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dylanmccrimmon/DUOSoftHardwareTokens/main/DUOSoftHardwareTokens.ps1' -OutFile 'DUOSoftHardwareTokens.ps1'
```

### Examples
#### Default

``` powershell
DUOSoftHardwareTokens.ps1 -DUOAPIHostName 'api-XXXXX.duosecurity.com' -DUOAPIIntegrationKey 'XXXXXXXX' -DUOAPISecretKey 'XXXXXXXXXXXXXX'


QR Code Link: https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=otpauth://totp/DUOHardwareToken(999-36507284)?secret=EGXNGO5GGUT542UTAIITH646MDXSKD6H&issuer=DUOSoftHardwareTokens&algorithm=SHA1&digits=6&period=30
Please enter the TOTP code displayed in your auth app? [OTP or Q to quit]: 458850
TOTP is correct. Authenticator application seems to be working correctly
Token data successfully sent to Duo. You can now manage the token in the Duo admin dashboard.
```

#### Skip TOTP user verification

``` powershell
DUOSoftHardwareTokens.ps1 -DUOAPIHostName 'api-XXXXX.duosecurity.com' -DUOAPIIntegrationKey 'XXXXXXXX' -DUOAPISecretKey 'XXXXXXXXXXXXXX' -SkipTOTPUserVerification


QR Code Link: https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=otpauth://totp/DUOHardwareToken(999-21870497)?secret=MDF2V6FGYMVAID2DTDMI3PKR3NNXGVLJ&issuer=DUOSoftHardwareTokens&algorithm=SHA1&digits=6&period=30
Token data successfully sent to Duo. You can now manage the token in the Duo admin dashboard. 
```

#### Output TOTP data

``` powershell
DUOSoftHardwareTokens.ps1 -DUOAPIHostName 'api-XXXXX.duosecurity.com' -DUOAPIIntegrationKey 'XXXXXXXX' -DUOAPISecretKey 'XXXXXXXXXXXXXX' -OutputTOTPData


QR Code Link: https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=otpauth://totp/DUOHardwareToken(999-52107829)?secret=KRCGNX3MLGMTGLRW5KJIFIS4HSGM4IQP&issuer=DUOSoftHardwareTokens&algorithm=SHA1&digits=6&period=30

Issuer    : DUOHardwareTokens
Account   : DUOHardwareToken(999-52107829)
Secret    : KRCGNX3MLGMTGLRW5KJIFIS4HSGM4IQP
Algorithm : HMAC-SHA-1
Digits    : 6
Period    : 30

Please enter the TOTP code displayed in your auth app? [OTP or Q to quit]: 984395
TOTP is correct. Authenticator application seems to be working correctly
Token data successfully sent to Duo. You can now manage the token in the Duo admin dashboard.
```


### Syntax

``` powershell
DUOSoftHardwareTokens.ps1
    [[-DUOAPIHostName] <String>]
    [[-DUOAPIIntegrationKey] <String>]
    [[-DUOAPISecretKey] <String>]
    [[-TOTPPeriod] <Int16>]
    [[-TOTPDigits] <Int16>]
    [-SkipTOTPUserVerification]
    [-OutputTOTPData]
    [<CommonParameters>]
```

### Parameters

#### -DUOAPIHostName 
Specifies the DUO API host name to use.

```yaml
Type: String
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

#### -DUOAPIIntegrationKey 
Specifies the DUO API intergration key.

```yaml
Type: String
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

#### -DUOAPISecretKey
Specifies the DUO API secret key.

```yaml
Type: String
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

#### -TOTPPeriod 
Specifies the TOTP period.

```yaml
Type: Int16
Accepted values: 30, 60
Required: False
Position: Named
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

#### -TOTPDigits 
Specifies the TOTP digits.

```yaml
Type: Int16
Accepted values: 6, 8
Required: False
Position: Named
Default value: 6
Accept pipeline input: False
Accept wildcard characters: False
```

#### -SkipTOTPUserVerification 
Specifies if the script should skip the user verification of the TOTP code.

```yaml
Type: Switch
Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

#### -SkipTOTPQRCodeLink 
Specifies if the script should skip displaying the QR Code link.

```yaml
Type: Switch
Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

#### -OutputTOTPData 
Specifies if the script should output PSCustomObject of the TOTP data.

```yaml
Type: Switch
Required: False
Position: Named
Default value: True
Accept pipeline input: False
Accept wildcard characters: False
```

## License
[Apache-2.0](https://choosealicense.com/licenses/apache-2.0/)
