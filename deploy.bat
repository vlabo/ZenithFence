echo Compile, Sign and Copy the Kernel Driver
set WDDK_SOURCE=install\WDDK\x64\Debug\pm_kernel64.sys
del WDDK_SOURCE

cargo build

msbuild /t:Clean /p:Configuration=Debug /p:Platform=x64
msbuild /t:Build /p:Configuration=Debug /p:Platform=x64
SignTool sign /v /s TestCertStoreName /n TestCertName /fd SHA256 %WDDK_SOURCE%

echo Copy the Kernel Driver to Portmaster updates dir as dev version
copy %WDDK_SOURCE% kext.sys
