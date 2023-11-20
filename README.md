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
PS C:\> Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dylanmccrimmon/DUOSoftHardwareTokens/main/DUOSoftHardwareTokens.ps1' -OutFile 'DUOSoftHardwareTokens.ps1'
```

#### Usage

``` powershell
PS C:\> DUOSoftHardwareTokens.ps1

SerialNumber    : 998-8129825
TOTPSecret      : NKNKLAU5PEEN5ZBL7U6MVUYPCOINNRB7
TOTPSecretKey   : 6A9AA5829D7908DEE42BFD3CCAD30F1390D6C43F
TOTPApplication : @{Secret=NKNKLAU5PEEN5ZBL7U6MVUYPCOINNRB7; Algorithm=SHA1; Digits=6; Period=30}
DUOCSVData      : 998-8129825,6A9AA5829D7908DEE42BFD3CCAD30F1390D6C43F,30
TOTPQRCodeData  : otpauth://totp/DUOHardwareToken(998-8129825)?secret=NKNKLAU5PEEN5ZBL7U6MVUYPCOINNRB7&algorithm=SHA1&digits=6&period=30
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
