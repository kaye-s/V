// Fade In
window.addEventListener("load", () => {
    document.body.classList.add("loaded");
});

window.addEventListener("DOMContentLoaded", () => {

    const hamburger = document.getElementById("hamburger");
    const sidebar = document.querySelector(".sidebar");
    const main = document.querySelector(".main");

    hamburger.addEventListener("click", () => {
        hamburger.classList.toggle("active");
        sidebar.classList.toggle("active");
        main.classList.toggle("shift");
    });

});