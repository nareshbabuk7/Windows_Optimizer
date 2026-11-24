@echo off
title WinPulse - Explainable Windows Service & Startup Optimizer
echo Starting WinPulse GUI...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinPulse.ps1"
