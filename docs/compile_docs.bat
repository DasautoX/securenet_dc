@echo off
REM SecureNet DC - LaTeX Document Compiler
REM Uses MikTeX to compile the lab document and solution report

echo ============================================
echo   SecureNet DC - Document Compiler
echo ============================================
echo.

REM Check if pdflatex is available
where pdflatex >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: pdflatex not found!
    echo Please install MikTeX from https://miktex.org/download
    echo Make sure to add MikTeX to your PATH
    pause
    exit /b 1
)

echo Compiling Lab Document...
echo -------------------------
pdflatex -interaction=nonstopmode lab_document.tex
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: First pass had issues, running again...
)
pdflatex -interaction=nonstopmode lab_document.tex
echo.

echo Compiling Solution Report...
echo ----------------------------
pdflatex -interaction=nonstopmode solution_report.tex
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: First pass had issues, running again...
)
pdflatex -interaction=nonstopmode solution_report.tex
echo.

REM Clean up auxiliary files
echo Cleaning up auxiliary files...
del /q *.aux *.log *.toc *.out 2>nul

echo.
echo ============================================
echo   Compilation Complete!
echo ============================================
echo.
echo Generated PDFs:
if exist lab_document.pdf (
    echo   [OK] lab_document.pdf
) else (
    echo   [FAILED] lab_document.pdf
)
if exist solution_report.pdf (
    echo   [OK] solution_report.pdf
) else (
    echo   [FAILED] solution_report.pdf
)
echo.
pause
