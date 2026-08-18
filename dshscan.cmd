@echo off
setlocal
node "%~dp0dist\main.js" %*
exit /b %errorlevel%
