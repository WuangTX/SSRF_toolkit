#  TOOLKIT LOCATION

## Current Directory
\\\
C:\Users\ASUS-PRO\Desktop\microservice_pentest_toolkit\
\\\

## Separated From Vulnerable App

This toolkit is now **independent** from the microservice lab application.

### Vulnerable App Location
\\\
C:\Users\ASUS-PRO\Desktop\microservice_lab\
\\\

### Why Separation?

1.  **Independence** - Toolkit can be used on any project
2.  **Portability** - Easy to copy to other systems
3.  **Clean structure** - No mixing of test tools with app code
4.  **Version control** - Can have separate git repos

---

## Quick Commands

### Test the Lab App
\\\powershell
# From toolkit directory
cd ..\microservice_lab
docker-compose up -d

# Scan from toolkit
cd ..\microservice_pentest_toolkit
python cli.py --mode blackbox --target http://localhost:8083
\\\

### Test Other Projects
\\\powershell
# Point to any target
python cli.py --mode blackbox --target http://your-app.com

# Scan any source code
python cli.py --mode whitebox --source-path C:\path\to\your\project
\\\

---

** Start Here**: Read \INDEX.md\ for complete navigation guide
