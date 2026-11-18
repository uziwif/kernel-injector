@echo off
cd /d "%~dp0"
echo ===== orelia run %DATE% %TIME% ===== > run.log
echo --- mapper (vulnerable driver -> Steam64) --- >> run.log
builds\orelia-mapper.exe builds\orelia-ioctl.sys <nul >> run.log 2>&1
echo MAPPER_EXIT=%ERRORLEVEL% >> run.log
echo --- injector (reflect into ROB RUN.exe) --- >> run.log
builds\ioctl-injector.exe "C:\Users\kitty\Downloads\RRTool_Public_[unknowncheats.me]_\amphetamine-robrun\client\build\RobRunInternal.dll" <nul >> run.log 2>&1
echo INJECTOR_EXIT=%ERRORLEVEL% >> run.log
echo --- done --- >> run.log
