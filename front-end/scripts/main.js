// Fade In
window.addEventListener("load", () => {
    document.body.classList.add("loaded");
});

window.addEventListener("DOMContentLoaded", () => {
    const hamburger = document.getElementById("hamburger");
    const sidebar = document.querySelector(".sidebar");
    const main = document.querySelector(".main");

    if (!hamburger || !sidebar) {
        return;
    }

    const syncAria = () => {
        const open = sidebar.classList.contains("active");
        hamburger.setAttribute("aria-expanded", open ? "true" : "false");
    };

    syncAria();

    hamburger.addEventListener("click", () => {
        hamburger.classList.toggle("active");
        sidebar.classList.toggle("active");
        if (main) {
            main.classList.toggle("shift");
        }
        syncAria();
    });

    hamburger.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
            ev.preventDefault();
            hamburger.click();
        }
    });

    const closeSidebar = () => {
        hamburger.classList.remove("active");
        sidebar.classList.remove("active");
        if (main) {
            main.classList.remove("shift");
        }
        syncAria();
    };

    sidebar.addEventListener("click", (ev) => {
        if (ev.target.closest("a.sidebar-link")) {
            closeSidebar();
        }
    });
});
