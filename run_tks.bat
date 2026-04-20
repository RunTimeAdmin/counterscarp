@echo off
set PATH=%PATH%;z:\Sentinal Engine\foundry-bin
cd /d "z:\Sentinal Engine\sentinel-engine"
python orchestrator.py --target "z:\Sentinal Engine\tokenkickstarter\smart-contracts" --report --project-name "TokenKickstarter Security Audit" > "z:\Sentinal Engine\tks_scan_output.txt" 2>&1
echo EXIT_CODE: %ERRORLEVEL% >> "z:\Sentinal Engine\tks_scan_output.txt"
echo DONE
