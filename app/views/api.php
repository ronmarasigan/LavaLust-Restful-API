<!DOCTYPE html>
<html>
<head>
  <title>Register</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body class="bg-light">

<div class="container mt-5">
  <div class="card p-4 shadow-sm">
    <h3 class="mb-3">Register</h3>

    <form id="registerForm">
      <div class="mb-3">
        <label>Username</label>
        <input type="text" class="form-control" name="username" required>
      </div>

      <div class="mb-3">
        <label>Email</label>
        <input type="email" class="form-control" name="email" required>
      </div>

      <div class="mb-3">
        <label>Password</label>
        <input type="password" class="form-control" name="password" required>
      </div>

      <button type="submit" class="btn btn-primary">Register</button>
    </form>

    <div id="result" class="mt-3"></div>
  </div>
</div>

<script>
  $('#registerForm').on('submit', function (e) {
    e.preventDefault();

    const formData = {
      username: $('input[name="username"]').val(),
      email: $('input[name="email"]').val(),
      password: $('input[name="password"]').val()
    };

    $.ajax({
      url: '/register',
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(formData),
      success: function (res) {
        $('#result').html(`<div class="alert alert-success">${res.message}</div>`);
        $('#registerForm')[0].reset();
      },
      error: function (xhr) {
        const msg = xhr.responseJSON?.message || 'Registration failed';
        $('#result').html(`<div class="alert alert-danger">${msg}</div>`);
      }
    });
  });
</script>

</body>
</html>
