@echo off
set "PATH=%PATH%;z:\Sentinal Engine\foundry-bin"
cd /d "z:\Sentinal Engine\sentinel-engine"
python orchestrator.py --target "z:\Sentinal Engine\ethernaut\contracts\src\levels" --report --project-name "Ethernaut v3.1.2 Full Battery" > "z:\Sentinal Engine\sentinel-engine\ethernaut_v312_out.txt" 2>&1
echo EXIT_CODE: %ERRORLEVEL% >> "z:\Sentinal Engine\sentinel-engine\ethernaut_v312_out.txt"
echo DONE
