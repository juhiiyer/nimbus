document.addEventListener("DOMContentLoaded", async () => {
    const searchBar = document.getElementById("searchBar");
    const container = document.getElementById("container");

    let drives = [];
    let isConnected = false;

    // Try to fetch connected drives from backend
    try {
        const response = await fetch("http://localhost:8000/drives");
        if (response.ok) {
            const data = await response.json();
            if (data.drives && data.drives.length > 0) {
                drives = data.drives;
                isConnected = true;
            }
        }
    } catch (e) {
        // Backend not reachable, treat as not connected
        isConnected = false;
    }

    // Create dropdown for search results
    let dropdown = document.createElement("ul");
    dropdown.style.position = "absolute";
    dropdown.style.background = "#fff";
    dropdown.style.border = "1px solid #ccc";
    dropdown.style.width = "90%";
    dropdown.style.maxHeight = "120px";
    dropdown.style.overflowY = "auto";
    dropdown.style.marginTop = "2px";
    dropdown.style.padding = "0";
    dropdown.style.listStyle = "none";
    dropdown.style.display = "none";
    dropdown.style.zIndex = "1000";
    container.appendChild(dropdown);

    // Redirect to login.html in a new tab if not connected
    searchBar.addEventListener("keydown", (e) => {
        if (!isConnected && e.key === "Enter") {
            chrome.tabs.create({ url: chrome.runtime.getURL("login.html") });
        }
    });

    // When a file is selected, open it in a new tab (replace with your file URL logic)
    function showDropdown(items) {
        dropdown.innerHTML = "";
        if (items.length === 0) {
            dropdown.style.display = "none";
            return;
        }
        items.forEach(item => {
            const li = document.createElement("li");
            li.textContent = item;
            li.style.padding = "8px";
            li.style.cursor = "pointer";
            li.addEventListener("mousedown", () => {
                searchBar.value = item;
                dropdown.style.display = "none";
                // Replace the URL below with your actual file URL logic
                chrome.tabs.create({ url: "https://your-drive-url.com/file/" + encodeURIComponent(item) });
            });
            dropdown.appendChild(li);
        });
        dropdown.style.display = "block";
    }

    searchBar.addEventListener("input", (e) => {
        const term = e.target.value.toLowerCase();
        if (isConnected && term) {
            const filtered = drives.filter(d => d.toLowerCase().includes(term));
            showDropdown(filtered);
        } else {
            dropdown.style.display = "none";
        }
    });

    // Hide dropdown on blur
    searchBar.addEventListener("blur", () => {
        setTimeout(() => { dropdown.style.display = "none"; }, 100);
    });
});