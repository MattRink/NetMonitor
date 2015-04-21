@echo off
SET THEFILE=NetMonitor.exe
echo Linking %THEFILE%
E:\Development\Lazarus\fpc\2.6.4\bin\i386-win32\ld.exe -b pei-i386 -m i386pe  --gc-sections    --entry=_mainCRTStartup    -o NetMonitor.exe link.res
if errorlevel 1 goto linkend
E:\Development\Lazarus\fpc\2.6.4\bin\i386-win32\postw32.exe --subsystem console --input NetMonitor.exe --stack 16777216
if errorlevel 1 goto linkend
goto end
:asmend
echo An error occured while assembling %THEFILE%
goto end
:linkend
echo An error occured while linking %THEFILE%
:end
