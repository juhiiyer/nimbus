// Global configuration for frontend -> backend API base URL
// Adjust this if your backend runs on a different host/port.
// Backend defaults to FastAPI on port 8000 per backend/main.py

// If window.API_BASE_URL is already defined before this file loads, keep it.
// Otherwise, default to http://localhost:8000
(function(){
  if (typeof window !== 'undefined') {
    if (!window.API_BASE_URL) {
      window.API_BASE_URL = 'http://localhost:8000';
    }
  }
})();
