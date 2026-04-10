// Page fade in
window.addEventListener("load", () => {
    document.body.classList.add("loaded");
});

// Animate login box
window.addEventListener("DOMContentLoaded", () => {
    const box = document.querySelector(".login-box");

    setTimeout(() => {
        box.classList.add("show");
    }, 150);
});

// Button loading state
const form = document.querySelector("form");
const button = document.querySelector(".login-btn");

form.addEventListener("submit", () => {
    button.innerText = "Logging in...";
    button.classList.add("loading");
    button.disabled = true;
});

// Shake on error (if Django renders error)
window.addEventListener("DOMContentLoaded", () => {
    const error = document.querySelector(".error");
    const box = document.querySelector(".login-box");

    if (error && box) {
        box.classList.add("shake");
    }
});