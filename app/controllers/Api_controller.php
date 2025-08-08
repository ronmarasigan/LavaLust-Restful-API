<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class Api_controller extends Controller {
    
    private $user_id;

    public function __construct()
    {
        parent::__construct();
    }

    public function login() 
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        $stmt = $this->db->raw('SELECT * FROM users WHERE username = ?', [$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $tokens = $this->api->issue_tokens(['id' => $user['id'], 'role' => $user['role']]);
            $this->api->respond($tokens);
        } else {
            $this->api->respond_error('Invalid credentials', 401);
        }
    }

    public function logout() {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $token = $input['refresh_token'] ?? '';
        $this->api->revoke_refresh_token($token);
        $this->api->respond(['message' => 'Logged out']);
    }

    public function list() {
        $stmt = $this->db->table('users')
                        ->select('id, username, email, role, created_at')
                        ->limit(2)
                        ->get_all();
        $this->api->respond($stmt);
    }

    public function create() {
        $input = $this->api->body();
        $this->db->raw("INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, ?, NOW())",[$input['username'], $input['email'], password_hash($input['password'], PASSWORD_BCRYPT), $input['role']]);
        $this->api->respond(['message' => 'User created']);
    }

    public function update($id) {
        $input = $this->api->body();
        $this->db->raw("UPDATE users SET username=?, email=?, role=? WHERE id=?", [$input['username'], $input['email'], $input['role'], $id]);
        $this->api->respond(['message' => 'User updated']);
    }

    public function delete($id) {
        $this->db->raw("DELETE FROM users WHERE id = ?", [$id]);
        $this->api->respond(['message' => 'User deleted']);
    }

    public function profile() {
        $auth = $this->api->require_jwt();
        $this->user_id = $auth['sub'];
        $stmt = $this->db->raw("SELECT id, username, email, role, created_at FROM users WHERE id = ?", [$this->user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $this->api->respond($user ?: ['message' => 'User not found']);
    }

    public function refresh() {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $refresh_token = $input['refresh_token'] ?? '';
        $this->api->refresh_access_token($refresh_token);
    }
}
?>
