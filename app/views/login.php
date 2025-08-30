<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login, Refresh, Logout</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
</head>
<body class="p-4">

<div class="container">
<h3 class="mb-4">API Login System</h3>

<div id="result"></div>

<!-- Login Form -->
<form id="login-form">
	<div class="mb-3">
	<label>Username or Email</label>
	<input type="text" name="username" class="form-control" required />
	</div>
	<div class="mb-3">
	<label>Password</label>
	<input type="password" name="password" class="form-control" required />
	</div>
	<button type="submit" class="btn btn-primary">Login</button>
</form>

<hr />

<button id="refresh-btn" class="btn btn-warning">Refresh Token</button>
<button id="logout-btn" class="btn btn-danger">Logout</button>
</div>
<script>
$(document).ready(function () {
const refresh_token = localStorage.getItem('refresh_token');
console.log(refresh_token);
if(refresh_token != "") {
	$('#login-form').hide();
	$('#refresh-btn').show();
	$('#logout-btn').show();	
}

// Login
$('#login-form').submit(function (e) {
	e.preventDefault();

	const formData = {
	username: $('input[name="username"]').val(),
	password: $('input[name="password"]').val()
	};

	$.ajax({
	url: '/login',
	method: 'POST',
	contentType: 'application/json',
	data: JSON.stringify(formData),
	success: function (res) {
		$('#result').html(`<div class="alert alert-success">${res.message}</div>`);
		localStorage.setItem('access_token', res.tokens.access_token);
		localStorage.setItem('refresh_token', res.tokens.refresh_token);
		$('#login-form').hide();
		$('#refresh-btn').show();
		$('#logout-btn').show();
	},
	error: function (xhr) {
		const msg = xhr.responseJSON?.message || 'Login failed';
		$('#result').html(`<div class="alert alert-danger">${msg}</div>`);
	}
	});
});

// Refresh Token
$('#refresh-btn').click(function () {
	const refresh_token = localStorage.getItem('refresh_token');
	//console.log(refresh_token);return;
	if (!refresh_token) return alert('No refresh token found.');

	$.ajax({
	url: '<?=site_url('refresh');?>',
	method: 'POST',
	contentType: 'application/json',
	data: JSON.stringify({ refresh_token }),
	success: function (res) {
	console.log("REFRESH RESPONSE:", res); // 👈 Check actual shape
	if (!res.tokens || !res.tokens.access_token) {
		$('#result').html(`<div class="alert alert-danger">Token data missing in response</div>`);
		return;
	}

	$('#result').html(`<div class="alert alert-success">${res.message}</div>`);
	localStorage.setItem('access_token', res.token.access_token);
	localStorage.setItem('refresh_token', res.token.refresh_token);
	
	
	},
	error: function (xhr) {
		const msg = xhr.responseJSON?.message || 'Token refresh failed';
		$('#result').html(`<div class="alert alert-danger">${msg}</div>`);
	}
	});
});

// Logout
$('#logout-btn').click(function () {
	const refresh_token = localStorage.getItem('refresh_token');
	if (!refresh_token) return alert('No refresh token found.');

	$.ajax({
	url: '<?=site_url('logout');?>',
	method: 'POST',
	contentType: 'application/json',
	data: JSON.stringify({ refresh_token }),
	success: function (res) {
		$('#result').html(`<div class="alert alert-info">${res.message}</div>`);
		localStorage.removeItem('access_token');
		localStorage.removeItem('refresh_token');
	},
	error: function (xhr) {
		const msg = xhr.responseJSON?.message || 'Logout failed';
		$('#result').html(`<div class="alert alert-danger">${msg}</div>`);
	}
	});
});
});
</script>
</body>
</html>