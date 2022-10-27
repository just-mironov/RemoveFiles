@echo off
title Remove files
powershell.exe while ($true) {%~dp0\Remove-Files.ps1}
pause