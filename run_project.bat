@echo off
title Cybersecurity Risk Assessment Framework for SMEs
echo ========================================================
echo  Cybersecurity Risk Assessment Framework for SMEs
echo  NIST CSF 2.0 Aligned
echo ========================================================
echo.
echo Starting web server at http://localhost:5000 ...
echo Opening application in default browser...
start http://localhost:5000
python backend\server.py 5000
pause
