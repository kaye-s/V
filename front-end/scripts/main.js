function operate(operator) {
	var num1 = document.querySelector('#num-1').value;
	var num2 = document.querySelector('#num-2').value;
	resultLambda = operator(num1, num2);
	resultLambda(result => {
		document.querySelector('#output').innerText = result;
	});
}

function loadUsers() {
	eel.showUsers()(users => {
		document.querySelector('#output').innerText = JSON.stringify(users, null, 2);
	});
}

function addUsers() {
	var email = document.querySelector('#email').value;
	var password = document.querySelector('#pass').value;

	eel.addUsers(email, password)(response => {
		document.querySelector('#output').innerText = response;
	});
}