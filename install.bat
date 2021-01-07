@echo off
echo Press enter to continue
pause >nul
cls
echo Processing.
ping 127.0.0.1 -n 1 >nul
cls
echo Processing..
ping 127.0.0.1 -n 1 >nul
cls
echo Processing...
ping 127.0.0.1 -n 1 >nul
cls
pip install sys
ping 127.0.0.1 -n 6 >nul
pip install socket
ping 127.0.0.1 -n 6 >nul
pip install time
ping 127.0.0.1 -n 6 >nul
pip install random
ping 127.0.0.1 -n 6 >nul
pip install threading
ping 127.0.0.1 -n 6 >nul
pip install getpass
ping 127.0.0.1 -n 6 >nul
pip install os
ping 127.0.0.1 -n 6 >nul
goto finish

:finish
echo installed!
pause
exit
