# DUOSoftHardwareTokens
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Script that create soft hardware tokens for DUO security. From the output, you can copy and paste the DUOCSVData field into DUO.

#### Installation / Download
<!-- ##### (Not yet working) Download from PowerShell Gallery
``` powershell
PS C:\> Install-Script -Name DUOSoftHardwareTokens
``` -->

##### Download from Github
``` powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dylanmccrimmon/DUOSoftHardwareTokens/main/DUOSoftHardwareTokens.ps1' -OutFile 'DUOSoftHardwareTokens.ps1'
```

### Usage

``` powershell
.\DUOSoftHardwareTokens.ps1

SerialNumber    : 998-8129825
TOTPSecret      : NKNKLAU5PEEN5ZBL7U6MVUYPCOINNRB7
TOTPSecretKey   : 6A9AA5829D7908DEE42BFD3CCAD30F1390D6C43F
TOTPApplication : @{Secret=NKNKLAU5PEEN5ZBL7U6MVUYPCOINNRB7; Algorithm=SHA1; Digits=6; Period=30}
DUOCSVData      : 998-8129825,6A9AA5829D7908DEE42BFD3CCAD30F1390D6C43F,30
TOTPQRCodeData  : otpauth://totp/DUOHardwareToken(998-8129825)?secret=NKNKLAU5PEEN5ZBL7U6MVUYPCOINNRB7&algorithm=SHA1&digits=6&period=30
```

### Parameters

#### -APIHostName 
Specifies the API host name to use.

```yaml
Type: String
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

#### -APIIntegrationKey 
Specifies the API intergration key.

```yaml
Type: String
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

#### -APISecretKey
Specifies the API secret key.

```yaml
Type: String
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

#### -TokenPeriod 
Specifies the TOTP token period.

```yaml
Type: Int16
Accepted values: 30, 60
Required: False
Position: Named
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

#### -TokenDigits 
Specifies the TOTP token digits.

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
