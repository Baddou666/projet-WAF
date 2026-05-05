@echo off
echo ======================================================
echo   GENERATION DE L'IMAGE DOCKER (WINDOWS)
echo ======================================================

:: Parsing des arguments

:: buildpush, push, build
set MODE=%1

:: final, test
set VERSION=%2

:: latest, v1.1.0,...
set TAG=%3

:: Defauts
if "%TAG%"=="" set TAG=latest

:: Verification de Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Docker n'est pas lance ou n'est pas installe.
    pause
    exit /b
)

:: Demander le mode d'operation si pas fourni
if "%MODE%"=="" (
    echo.
    echo ======================================================
    echo   CHOIX DU MODE D'OPERATION
    echo ======================================================
    echo Que voulez-vous faire ?
    echo 1. Build et push
    echo 2. Seulement build
    echo 3. Seulement push
    echo.
    set /p mode="Entrez 1, 2 ou 3 : "
) else (
    set mode=%MODE%
)

if "%mode%"=="1" set mode=buildpush
if "%mode%"=="2" set mode=build
if "%mode%"=="3" set mode=push
if "%mode%"=="buildpush" goto build_and_push
if "%mode%"=="build" goto only_build
if "%mode%"=="push" goto only_push
echo [ERREUR] Mode invalide(%mode%). Utilisez build, push ou buildpush.
pause
exit /b

:only_build
echo [1/2] Construction de l'image Docker...
docker build -f Dockerfile -t waf-open-source:latest .

if %errorlevel% neq 0 (
    echo [ERREUR] Le build Docker a echoue.
    pause
    exit /b
)

echo [2/2] Liste des images generees :
docker images | findstr "waf-open-source"

echo ======================================================
echo   TERMINE : L'image est prete localement.
echo ======================================================
pause
exit /b

:build_and_push
echo [1/3] Construction de l'image Docker...
docker build -f Dockerfile -t waf-open-source:latest .

if %errorlevel% neq 0 (
    echo [ERREUR] Le build Docker a echoue.
    pause
    exit /b
)

echo [2/3] Liste des images generees :
docker images | findstr "waf-open-source"

goto choose_version

:only_push
:: Verifier si l'image existe
docker images | findstr "waf-open-source" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Aucune image waf-open-source trouvee localement. Faites un build d'abord.
    pause
    exit /b
)

echo Image waf-open-source trouvee localement.
goto choose_version

:choose_version
:: Utiliser les arguments ou demander

if "%VERSION%"=="" (
    echo.
    echo ======================================================
    echo   CHOIX DE LA VERSION A POUSSER:
    echo ======================================================
    echo Choisissez la version :
    echo 1. Test "ghcr.io/dazinenoamane/projet-waf/waf-open-source"
    echo 2. Final "ghcr.io/dazinenoamane/projet-waf/waf-open-source"
    echo.
    set /p choice="Entrez 1 pour Test, 2 pour Final : "
) else (
    if "%VERSION%"=="test" set choice=1
    if "%VERSION%"=="final" set choice=2
    call :check_choice
)

if "%choice%"=="1" (
    set BASE_TAG=ghcr.io/dazinenoamane/projet-waf/waf-open-source
    echo Version Test selectionnee.
) else if "%choice%"=="2" (
    set BASE_TAG=ghcr.io/dazinenoamane/projet-waf/waf-open-source
    echo Version Final selectionnee.
) else (
    set BASE_TAG=ghcr.io/dazinenoamane/projet-waf/waf-open-source
    echo Version Final selectionnee par defaut.
)

if "%3"=="" (
    echo.
    set /p tag="Entrez le tag de version (latest par defaut) : "
    if "%tag%"=="" set tag=latest
) else (
    set tag=%TAG%
)
set IMAGE_TAG=%BASE_TAG%:%tag%

echo [3/3] Tag et push de l'image...
docker tag waf-open-source:latest %IMAGE_TAG%
docker push %IMAGE_TAG%

if %errorlevel% neq 0 (
    echo [ERREUR] Echec du push de l'image.
    pause
    exit /b
)

echo ======================================================
echo   TERMINE : L'image a ete poussee vers %IMAGE_TAG%
echo ======================================================
pause

:check_choice
if "%choice%"=="" (
    echo [ERREUR] Version invalide:'%VERSION%'. Utilisez test ou final.
    pause
    exit /b
)
goto :EOF

