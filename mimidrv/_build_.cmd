@echo off
set winddk=%SystemDrive%\WinDDK\7600.16385.1

set mimidrv=%~dp0
set path=%systemroot%;%systemroot%\system32
set origplatform=%1
set destination=%2

if %origplatform%==Win32 (
	set platform=x86
	set beginsource=x86
	set endsource=i386
)  else (
	set platform=x64
	set beginsource=amd64
	set endsource=amd64
)

if exist %winddk% (
	call %winddk%\bin\setenv.bat %winddk%\ fre %platform% WNET no_oacr
	cd /d %mimidrv%
	build
	if errorlevel 0 (copy /y %mimidrv%\objfre_wnet_%beginsource%\%endsource%\*.sys %destination%) else echo Build failed :(
) else echo No WDK found :(

rd /s /q %mimidrv%\obj
rd /s /q %mimidrv%\%origplatform%