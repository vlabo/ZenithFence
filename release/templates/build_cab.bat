@echo off
del {{version_file}}.cab

link.exe /OUT:{{sys_file}} /RELEASE /DEBUG /NOLOGO /NXCOMPAT /NODEFAULTLIB /SUBSYSTEM:NATIVE /DRIVER /DYNAMICBASE /MANIFEST:NO /PDBALTPATH:none /MACHINE:X64 /OPT:REF,ICF /MACHINE:X64 /SUBSYSTEM:NATIVE,6.01 /ENTRY:FxDriverEntry "/MERGE:.edata=.rdata;_TEXT=.text;_PAGE=PAGE" /MERGE:.rustc=.data /INTEGRITYCHECK {{lib_file}}

move {{sys_file}} cab\\{{sys_file}}
move {{pdb_file}} cab\\{{pdb_file}}

echo.
echo =====
echo creating .cab ...
MakeCab /f {{version_file}}.ddf

echo.
echo =====
echo cleaning up ...
del setup.inf
del setup.rpt
move disk1\\{{version_file}}.cab {{version_file}}.cab
rmdir disk1

echo.
echo =====
echo YOUR TURN: sign the .cab
echo use something along the lines of:
echo.
echo signtool sign /sha1 C2CBB3A0256A157FEB08B661D72BF490B68724C4 /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a {{version_file}}.cab
echo.