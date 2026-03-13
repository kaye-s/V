console.log("main.js loaded")
document.addEventListener("DOMContentLoaded", function () {
	const tabButtons = document.querySelectorAll(".tab-btn");
	const tabContents = document.querySelectorAll(".tab-content");
	const startScanBtn = document.getElementById("startScanBtn");			//start scan
	const loginBtn = document.getElementById("loginBtn");					//login
	const registerBtn = document.getElementById("registerBtn"); 			//register

	tabButtons.forEach(button => {
		button.addEventListener("click", function () {
			const targetTab = this.dataset.tab;

			tabButtons.forEach(btn => btn.classList.remove("active"));
			tabContents.forEach(content => content.classList.remove("active"));

			this.classList.add("active");
			document.getElementById(targetTab).classList.add("active");
		});
	});

	if (startScanBtn) {
		startScanBtn.addEventListener("click", startScan);
	}
	if(loginBtn){
		loginBtn.addEventListener("click", loginUser);
	}
	if(registerBtn){
		registerBtn.addEventListener("click", registerUser);
	}
});

//Start code scan
async function startScan() {
	const code = document.getElementById("codeInput").value.trim();
	const resultsBox = document.getElementById("scanResults");

	if (!code) {
		alert("Please paste code to analyze.");
		return;
	}

	resultsBox.innerHTML = "Starting scan...";

	try {
		const response = await fetch("/api/analysis/", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-CSRFToken": getCookie("csrftoken")
			},
			body: JSON.stringify({
				code: code,
				language: "python"
			})
		});

		const text = await response.text();
		console.log("Raw response:", text);

		let data;
		try {
			data = JSON.parse(text);
		} catch {
			resultsBox.innerHTML = `Server returned non-JSON response. Status: ${response.status}`;
			return;
		}

		if (!response.ok) {
			resultsBox.innerHTML = `Error: ${JSON.stringify(data)}`;
			return;
		}

		const taskId = data.task_id;
		resultsBox.innerHTML = `Scan started. Task ID: ${taskId}`;
		checkStatus(taskId);

	} catch (error) {
		console.error(error);
		resultsBox.innerHTML = `Error: ${error.message}`;
	}
}

//Show Task Status
function checkStatus(taskId) {
	const resultsBox = document.getElementById("scanResults");

	const interval = setInterval(async () => {
		try {
			const response = await fetch(`/api/analysis/${taskId}/`);
			const data = await response.json();

			if (!response.ok) {
				clearInterval(interval);
				resultsBox.innerHTML = `Error: ${JSON.stringify(data)}`;
				return;
			}

			resultsBox.innerHTML = `Status: ${data.status}`;

			if (data.status === "COMPLETED") {
				clearInterval(interval);
				resultsBox.innerHTML =
					"<h3>Scan Complete</h3><pre>" +
					JSON.stringify(data.summary, null, 2) +
					"</pre>";
			}

			if (data.status === "FAILED") {
				clearInterval(interval);
				resultsBox.innerHTML = "Scan failed.";
			}
		} catch (error) {
			clearInterval(interval);
			console.error(error);
			resultsBox.innerHTML = `Error: ${error.message}`;
		}
	}, 2000);
}

//Login
async function loginUser() {

	const username = document.getElementById("username").value;
	const password = document.getElementById("password").value;

	try {

		const response = await fetch("/api/login/", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-CSRFToken": getCookie("csrftoken")
			},
			credentials: "same-origin",
			body: JSON.stringify({
				username: username,
				password: password
			})
		});

		const data = await response.json();

		if (!response.ok) {
			alert(data.error || "Login failed");
			return;
		}

		// redirect to dashboard
		window.location.href = "/";

	} catch (error) {
		console.error(error);
		alert("Login error");
	}
}

//Registration
async function registerUser() {
	const username = document.getElementById("username").value;
	const password = document.getElementById("password").value;

	try {
		const response = await fetch("/api/register/", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-CSRFToken": getCookie("csrftoken")
			},
			credentials: "same-origin",
			body: JSON.stringify({
				username: username,
				password: password
			})
		});

		const data = await response.json();

		if (!response.ok) {
			alert(data.error || "Registration failed");
			return;
		}

		window.location.href = "/";
	} catch (error) {
		console.error(error);
		alert("Register error");
	}
}

//Get CSRF token
function getCookie(name) {
	let cookieValue = null;
	if (document.cookie && document.cookie !== "") {
		const cookies = document.cookie.split(";");
		for (let i = 0; i < cookies.length; i++) {
			const cookie = cookies[i].trim();
			if (cookie.substring(0, name.length + 1) === (name + "=")) {
				cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
				break;
			}
		}
	}
	return cookieValue;
}