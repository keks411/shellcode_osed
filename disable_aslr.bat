@echo off
echo Disabling ASLR...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v MoveImages /t REG_DWORD /d 0 /f
echo ASLR has been disabled.

