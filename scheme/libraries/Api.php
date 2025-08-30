<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class Api
{
    private $_lava;
    protected $refresh_token_table;
    protected $payload_token_expiration;
    protected $refresh_token_expiration;
    protected $allow_origin;
    private $jwt_secret;
    private $refresh_token_key;

    public function __construct()
    {
        $this->_lava =& lava_instance();
        $this->_lava->config->load('api');

        if (!config_item('api_helper_enabled')) {
            show_error('Api Helper is disabled or set up incorrectly.');
        }

        $this->refresh_token_table     = config_item('refresh_token_table');
        $this->payload_token_expiration = config_item('payload_token_expiration');
        $this->refresh_token_expiration = config_item('refresh_token_expiration');
        $this->jwt_secret              = config_item('jwt_secret');
        $this->refresh_token_key       = config_item('refresh_token_key');
        $this->allow_origin            = config_item('allow_origin');

        // Handle CORS
        $this->handle_cors();

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
    }

    // --------------------------
    // Basic Utilities
    // --------------------------
    public function handle_cors()
    {
        header("Access-Control-Allow-Origin: {$this->allow_origin}");
        header("Access-Control-Allow-Headers: Authorization, Content-Type");
        header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
        header("Content-Type: application/json; charset=UTF-8");
    }

    public function body()
    {
        $contentType = $_SERVER["CONTENT_TYPE"] ?? '';

        if (stripos($contentType, 'application/json') !== false) {
            $input = json_decode(file_get_contents("php://input"), true);
            return is_array($input) ? $input : [];
        }

        if ($_POST) return $_POST;

        parse_str(file_get_contents("php://input"), $formData);
        return $formData;
    }

    public function get_query_params()
    {
        return $_GET;
    }

    public function require_method(string $method)
    {
        if ($_SERVER['REQUEST_METHOD'] !== strtoupper($method)) {
            $this->respond_error("Method Not Allowed", 405);
        }
    }

    public function respond($data, $code = 200)
    {
        http_response_code($code);
        echo json_encode($data);
        exit;
    }

    public function respond_error($message, $code = 400)
    {
        $this->respond(['error' => $message], $code);
    }

    // --------------------------
    // Auth: JWT
    // --------------------------
    private function base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

private function base64url_decode($data)
{
    return base64_decode(strtr($data, '-_', '+/'));
}

public function encode_jwt($payload)
{
    $header = $this->base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = $this->base64url_encode(json_encode($payload));
    $signature = $this->base64url_encode(
        hash_hmac('sha256', "$header.$payload", $this->jwt_secret, true)
    );
    return "$header.$payload.$signature";
}

public function decode_jwt($token)
{
    if (!is_string($token) || trim($token) === '') {
        return false;
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    list($header, $payload, $signature) = $parts;

    $valid_sig = $this->base64url_encode(
        hash_hmac('sha256', "$header.$payload", $this->jwt_secret, true)
    );

    if (!hash_equals($valid_sig, $signature)) {
        return false;
    }

    $decoded = json_decode($this->base64url_decode($payload), true);

    // check expiration if exists
    if (isset($decoded['exp']) && time() >= $decoded['exp']) {
        return false;
    }

    return $decoded;
}


    public function validate_jwt($token)
    {
        $payload = $this->decode_jwt($token);
        if (!$payload) return false;

        if (!isset($payload['sub'], $payload['iat'], $payload['exp'])) return false;
        if ($payload['exp'] < time()) return false;

        return $payload;
    }

    /**
     * More robust token header extraction
     */
    public function get_bearer_token()
    {
        $header = null;

        // Most common
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = $_SERVER['HTTP_AUTHORIZATION'];
        }
        // Nginx/FastCGI
        elseif (isset($_SERVER['Authorization'])) {
            $header = $_SERVER['Authorization'];
        }
        // Apache specific
        elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers['Authorization'])) {
                $header = $headers['Authorization'];
            }
        }
        // CGI/FPM redirect
        elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }

        if ($header && preg_match('/Bearer\s+(\S+)/', $header, $matches)) {
            return $matches[1];
        }
        return null;
    }

    public function require_jwt()
    {
        $token = $this->get_bearer_token();
        if (empty($token)) {
            $this->respond_error('Missing bearer token', 401);
        }

        $payload = $this->validate_jwt($token);
        if (!$payload) {
            $this->respond_error('Unauthorized or expired token', 401);
        }

        return $payload;
    }

    // --------------------------
    // Token System
    // --------------------------
    public function issue_tokens(array $user_data)
    {
        $user_id = $user_data['id'];
        $now     = time();
        $scopes  = $user_data['scopes'] ?? ['read'];

        $access_payload = [
            'sub'    => $user_id,
            'role'   => $user_data['role'] ?? 'user',
            'scopes' => $scopes,
            'iat'    => $now,
            'exp'    => $now + $this->payload_token_expiration
        ];

        $refresh_payload = [
            'sub'  => $user_id,
            'type' => 'refresh',
            'iat'  => $now,
            'exp'  => $now + $this->refresh_token_expiration
        ];

        $access_token        = $this->encode_jwt($access_payload);
        $refresh_token_raw   = $this->encode_jwt($refresh_payload);
        $refresh_token_stored = $this->encrypt_token($refresh_token_raw);

        $this->cleanup_expired_refresh_tokens($user_id);
        $this->_lava->db->raw(
            'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            [$user_id, $refresh_token_stored, date('Y-m-d H:i:s', $refresh_payload['exp'])]
        );

        return [
            'access_token'  => $access_token,
            'refresh_token' => $refresh_token_raw,
            'expires_in'    => $this->payload_token_expiration
        ];
    }

    public function refresh_access_token($refresh_token)
    {
        if (empty($refresh_token)) {
            $this->respond_error('Missing refresh token', 401);
        }

        $payload = $this->validate_jwt($refresh_token);
        if (!$payload || ($payload['type'] ?? '') !== 'refresh') {
            $this->respond_error('Invalid refresh token', 403);
        }

        $encrypted = $this->encrypt_token($refresh_token);
        $stmt = $this->_lava->db->raw('SELECT * FROM refresh_tokens WHERE token = ? LIMIT 1', [$encrypted]);
        $found = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$found || strtotime($found['expires_at']) < time()) {
            $this->respond_error('Refresh token expired or not found', 403);
        }

        $this->revoke_refresh_token($refresh_token);
        $new = $this->issue_tokens(['id' => $payload['sub']]);
        $this->respond([
            'message' => 'Token refreshed successfully',
            'tokens'  => $new
        ]);
    }

    public function revoke_refresh_token($refresh_token)
    {
        $encrypted = $this->encrypt_token($refresh_token);
        $this->_lava->db->raw('DELETE FROM refresh_tokens WHERE token = ?', [$encrypted]);
    }

    public function cleanup_expired_refresh_tokens($user_id)
    {
        $this->_lava->db->raw('DELETE FROM refresh_tokens WHERE user_id = ? AND expires_at < NOW()', [$user_id]);
    }

    private function encrypt_token($token)
    {
        $key = hash('sha256', $this->refresh_token_key);
        $iv  = substr(hash('sha256', 'static_iv'), 0, 16);
        return openssl_encrypt($token, 'AES-256-CBC', $key, 0, $iv);
    }

    public function decrypt_token($encrypted)
    {
        $key = hash('sha256', $this->refresh_token_key);
        $iv  = substr(hash('sha256', 'static_iv'), 0, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }

    // --------------------------
    // Basic Auth
    // --------------------------
    public function check_basic_auth($valid_user, $valid_pass)
    {
        $user = $_SERVER['PHP_AUTH_USER'] ?? '';
        $pass = $_SERVER['PHP_AUTH_PW'] ?? '';
        return ($user === $valid_user && $pass === $valid_pass);
    }

    public function require_basic_auth($valid_user, $valid_pass)
    {
        if (!$this->check_basic_auth($valid_user, $valid_pass)) {
            header('WWW-Authenticate: Basic realm="Restricted"');
            $this->respond_error('Unauthorized', 401);
        }
    }
}
