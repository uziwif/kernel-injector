@echo off
cd /d "%~dp0"
set MSB="C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
%MSB% orelia-injector\orelia-injector.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m /v:m
echo INJECTOR_EXIT=%ERRORLEVEL%
%MSB% orelia-mapper\orelia-mapper.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m /v:m
echo MAPPER_EXIT=%ERRORLEVEL%
