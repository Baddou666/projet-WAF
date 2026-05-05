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
docker build -f Dockerfile -t waf-custom:latest .

if %errorlevel% neq 0 (
    echo [ERREUR] Le build Docker a echoue.
    pause
    exit /b
)

echo [2/2] Liste des images generees :
docker images | findstr "waf-custom"

echo ======================================================
echo   TERMINE : L'image est prete localement.
echo ======================================================
pause
exit /b

:build_and_push
echo [1/4] Construction de l'image Docker...
docker build -f Dockerfile -t waf-custom:latest .

if %errorlevel% neq 0 (
    echo [ERREUR] Le build Docker a echoue.
    pause
    exit /b
)

echo [2/4] Liste des images generees :
docker images | findstr "waf-custom"

goto choose_version

:only_push
:: Verifier si l'image existe
docker images | findstr "waf-custom" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Aucune image waf-custom trouvee localement. Faites un build d'abord.
    pause
    exit /b
)

echo Image waf-custom trouvee localement.
goto choose_version

:choose_version
:: Utiliser les arguments ou demander

if "%VERSION%"=="" (
    echo.
    echo ======================================================
    echo   CHOIX DE LA VERSION A POUSSER:
    echo ======================================================
    echo Choisissez la version :
    echo 1. Test "ghcr.io/dazinenoamane/projet-waf/waf-custom"
    echo 2. Final "ghcr.io/dazinenoamane/projet-waf/waf-custom"
    echo.
    set /p choice="Entrez 1 pour Test, 2 pour Final : "
) else (
    if "%VERSION%"=="test" set choice=1
    if "%VERSION%"=="final" set choice=2
    call :check_choice
)

if "%choice%"=="1" (
    set BASE_TAG=ghcr.io/dazinenoamane/projet-waf/waf-custom
    echo Version Test selectionnee.
) else if "%choice%"=="2" (
    set BASE_TAG=ghcr.io/dazinenoamane/projet-waf/waf-custom
    echo Version Final selectionnee.
) else (
    set BASE_TAG=ghcr.io/dazinenoamane/projet-waf/waf-custom
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

:: Verification de la cle API
if "%gitapi%"=="" (
    echo [ERREUR] La variable d'environnement gitapi n'est pas definie. Authentification impossible.
    pause
    exit /b
)

echo [3/4] Authentification a GHCR...
echo %gitapi% | docker login ghcr.io -u dazinenoamane --password-stdin
if %errorlevel% neq 0 (
    echo [ERREUR] Echec de l'authentification a GHCR.
    pause
    exit /b
)

echo [4/4] Tag et push de l'image...
docker tag waf-custom:latest %IMAGE_TAG%
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

