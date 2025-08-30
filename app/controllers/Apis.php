<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class Apis extends Controller {
    
    public function __construct()
    {
        parent::__construct();
        
    }

    public function register() {

        if($this->io->method() == 'post') {
            $this->api->handle_cors();
            $this->api->require_method('POST');
            $input = $this->api->get_json_input();

            if (!isset($input['username'], $input['email'], $input['password'])) {
                $this->api->respond_error('Missing username, email, or password', 400);
            }

            $username = $input['username'];
            $email = $input['email'];
            $password = $input['password'];

            // Basic validation
            if (strlen($username) < 3 || strlen($password) < 6) {
                $this->api->respond_error('Username must be at least 3 characters and password at least 6 characters', 400);
            }
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->api->respond_error('Invalid email format', 400);
            }

            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            try {
                $stmt = $this->db->raw("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", [$username, $email, $password_hash]);
                $this->api->respond(['message' => 'User registered successfully']);
            } catch (PDOException $e) {
                
                $this->api->respond_error('Registration failed:' . $e->getMessage(), 500);
            }
        }
        $this->call->view('api');
        
    }

    public function login() {
        if($this->io->method() === 'post') {
            $this->api->handle_cors();
            $this->api->require_method('POST');

            $input = $this->api->get_json_input();

            if (!isset($input['username'], $input['password'])) {
                $this->api->respond_error('Missing username or password', 400);
            }

            $username = $input['username'];
            $password = $input['password'];

            try {
                $stmt = $this->db->raw("SELECT id, username, password_hash, role FROM users WHERE username = ?", [$username]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user && password_verify($password, $user['password_hash'])) {
                    // Issue access and refresh tokens
                    // 🎫 Issue both access & refresh tokens
                    $tokens = $this->api->issue_tokens([
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'role' => $user['role']
                    ]);

                    // ✅ Return success response
                    $this->api->respond([
                        'message' => 'Login successful',
                        'user' => [
                            'id' => $user['id'],
                            'username' => $user['username'],
                        ],
                        'tokens' => $tokens
                    ]);
                } else {
                    $this->api->respond_error('Invalid credentials', 401);
                }
            } catch (PDOException $e) {
                $this->api->respond_error('Login failed: ' . $e->getMessage(), 500);
            }
        }
        $this->call->view('login');
    }

    public function logout() {
        $this->api->handle_cors();
        $input = $this->api->get_json_input();

        if (empty($input['refresh_token'])) {
            $this->api->respond_rrror("Refresh token required", 400);
        }

        $this->api->revoke_refresh_token($input['refresh_token']);
        $this->api->respond(["message" => "Logged out successfully"]);
    }

    public function profile() {
        $this->api->handle_cors();
        $this->api->require_method('GET');
        $payload = $this->api->require_jwt(); // Requires a valid access token

        $user_id = $payload['sub'];

        try {
            $stmt = $this->db->raw("SELECT id, username, email, role, created_at FROM users WHERE id = ?", [$user_id]);
            $user_profile = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user_profile) {
                $this->api->respond($user_profile);
            } else {
                $this->api->respond_error('User profile not found', 404);
            }
        } catch (PDOException $e) {
            $this->api->respond_error('Failed to retrieve profile: ' . $e->getMessage(), 500);
        }
    }

    public function refresh() {
        if($this->io->method() === 'post') {
            $this->api->handle_cors();
            $data = $this->api->get_json_input();
            $refreshToken = $data['refresh_token'] ?? null;
            //echo $refreshToken;exit;
            if (!$refreshToken) {
                $this->api->respond_error('Missing refresh token', 400);
            }
            
            $this->api->refresh_access_token($refreshToken);
            
        }
        
    }
}
?>
