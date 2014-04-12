@echo off
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

del /f /q /a %destination%\*.sys
rd /s /q %mimidrv%\obj
rd /s /q %mimidrv%\objfre_wnet_%beginsource%
del /f /q /a %mimidrv%\buildfre_wnet_%beginsource%.log