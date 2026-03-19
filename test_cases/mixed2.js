function renderSafe(msg) {
  document.getElementById("safe").textContent = msg;
}

function renderUnsafe(msg) {
  document.getElementById("unsafe").innerHTML = msg;
}

function calculate(a, b) {
  return a + b;
}