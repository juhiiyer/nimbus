# Run FastAPI backend with uvicorn on http://localhost:8000 (reload enabled)
# Requires dependencies installed in your virtual environment.
# Usage: ./run-backend.ps1

$ErrorActionPreference = "Stop"

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
  & $venvPython -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
} else {
  Write-Host ".venv not found. Falling back to system python."
  python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
}
