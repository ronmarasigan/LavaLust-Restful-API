<?php

class Api
{
    /**
     * LavaLust Super Object
     *
     * @var object
     */
    private $_lava;

    /**
     * Api Refresh Token Table
     *
     * @var string
     */
    protected $refresh_token_table = 'refresh_tokens';

    /**
     * Allow Origin
     *
     * @var string
     */
    protected $allow_origin = '*';

    /**
     * Secret Code
     *
     * @var string
     */
    private $jwt_secret = '';

    /**
     * Refresh Token
     *
     * @var string
     */
    private $refresh_token_key = '';

    public function __construct()
    {
        $this->_lava =& lava_instance();

        $this->_lava->config->load('api');

        if(! config_item('api_helper_enabled')) {
            show_error('Api Helper is disabled or set up incorrectly.');
        }

        $this->refresh_token_table = config_item('refresh_token_table');

        $this->allow_origin = config_item('allow_origin');

        //Handle CORS
        $this->handle_cors();

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
    }

    // --------------------------
    // Basic Utilities
    // --------------------------
    /**
     * handle cors
     *
     * @return void
     */
    public function handle_cors()
    {
        header("Access-Control-Allow-Origin: {$this->allow_origin}");
        header("Access-Control-Allow-Headers: Authorization, Content-Type");
        header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
        header("Content-Type: application/json; charset=UTF-8");
    }

    /**
     * API body
     *
     * @return void
     */
    public function body()
    {
        $contentType = $_SERVER["CONTENT_TYPE"] ?? '';

        // JSON input
        if (stripos($contentType, 'application/json') !== false) {
            $input = json_decode(file_get_contents("php://input"), true);
            return is_array($input) ? $input : [];
        }

        // Form data fallback
        if ($_POST) {
            return $_POST;
        }

        // Raw fallback for form-encoded bodies
        parse_str(file_get_contents("php://input"), $formData);
        return $formData;
    }

    /**
     * get_query_params
     *
     * @return void
     */
    public function get_query_params()
    {
        return $_GET;
    }

    /**
     * require_method
     *
     * @param string $method
     * @return void
     */
    public function require_method(string $method)
    {
        if ($_SERVER['REQUEST_METHOD'] !== strtoupper($method)) {
            $this->respond_error("Method Not Allowed", 405);
        }
    }

    /**
     * respond
     *
     * @param mixed $data
     * @param integer $code
     * @return void
     */
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

    private function base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

private function base64url_decode($data)
{
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}

    // --------------------------
    // Auth: JWT
    // --------------------------
    public function encode_jwt(array $payload)
{
    $header = $this->base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $body   = $this->base64url_encode(json_encode($payload));
    $signatureRaw = hash_hmac('sha256', "{$header}.{$body}", $this->jwt_secret, true);
    $signature = $this->base64url_encode($signatureRaw);
    return "{$header}.{$body}.{$signature}";
}

public function decode_jwt($token)
{
    // Defensive: must be non-empty string
    if (!is_string($token) || trim($token) === '') {
        return false;
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;
    [$headerB64, $payloadB64, $signatureB64] = $parts;

    // Recreate signature using URL-safe base64
    $expectedRaw = hash_hmac('sha256', "{$headerB64}.{$payloadB64}", $this->jwt_secret, true);
    $expectedSig = $this->base64url_encode($expectedRaw);

    // Use hash_equals to prevent timing attacks
    if (!is_string($signatureB64) || !hash_equals($expectedSig, $signatureB64)) {
        return false;
    }

    $payloadJson = $this->base64url_decode($payloadB64);
    if ($payloadJson === false) return false;

    $payload = json_decode($payloadJson, true);
    return is_array($payload) ? $payload : false;
}


    /**
     * validate_jwt
     *
     * @param string $token
     * @return void
     */
    public function validate_jwt($token)
{
    $payload = $this->decode_jwt($token);
    if (!$payload) return false;
    if (!isset($payload['sub'], $payload['iat'], $payload['exp'])) return false;
    if ($payload['exp'] < time()) return false;
    return $payload;
}

// helper - normalize headers (works on many servers)
private function get_all_request_headers()
{
    if (function_exists('getallheaders')) {
        $h = getallheaders();
        if (is_array($h)) return $h;
    }

    if (function_exists('apache_request_headers')) {
        $h = apache_request_headers();
        if (is_array($h)) return $h;
    }

    // Fallback: gather from $_SERVER
    $headers = [];
    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) === 'HTTP_') {
            $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
            $headers[$key] = $value;
        }
    }

    if (isset($_SERVER['CONTENT_TYPE'])) $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
    if (isset($_SERVER['CONTENT_LENGTH'])) $headers['Content-Length'] = $_SERVER['CONTENT_LENGTH'];

    return $headers;
}

public function get_bearer_token()
{
    // Try several locations and normalize
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';

    if (empty($header)) {
        $all = $this->get_all_request_headers();
        // Normalize key names (some servers use lowercase)
        foreach ($all as $k => $v) {
            if (strtolower($k) === 'authorization') {
                $header = $v;
                break;
            }
        }
    }

    // If still empty, return null
    if (empty($header)) return null;

    // Accept formats: "Bearer <token>" or just "<token>"
    if (preg_match('/Bearer\s+(\S+)/i', $header, $matches)) {
        return $matches[1];
    }

    // If header contains a token without "Bearer"
    $header = trim($header);
    if ($header !== '') return $header;

    return null;
}


    /**
     * require_jwt
     *
     * @return void
     */
public function require_jwt() {
    $token = null;

    // Try normal header
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $authHeader = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        // Sometimes Apache puts it here
        $authHeader = trim($_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        // Try apache_request_headers
        $headers = apache_request_headers();
        if (isset($headers['Authorization'])) {
            $authHeader = trim($headers['Authorization']);
        }
    }

    if (!empty($authHeader) && preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $token = $matches[1];
    }

    if (!$token) {
        $this->respond_error('Authorization token not found', 401);
    }

    $decoded = $this->decode_jwt($token);

    if (!$decoded) {
        $this->respond_error('Invalid token', 401);
    }

    return $decoded;
}


    // --------------------------
    // Auth: Token System
    // --------------------------
    /**
     * issue_tokens
     *
     * @param array $user_data
     * @return void
     */
    public function issue_tokens(array $user_data)
    {
        $user_id = $user_data['id'];
        $now = time();
        $scopes = $user_data['scopes'] ?? ['read'];

        $access_payload = [
            'sub' => $user_id,
            'role' => $user_data['role'] ?? 'user',
            'scopes' => $scopes,
            'iat' => $now,
            'exp' => $now + 900
        ];

        $refresh_payload = [
            'sub' => $user_id,
            'type' => 'refresh',
            'iat' => $now,
            'exp' => $now + 604800
        ];

        $access_token = $this->encode_jwt($access_payload);
        $refresh_token_raw = $this->encode_jwt($refresh_payload);
        $refresh_token_encrypted = $this->encrypt_token($refresh_token_raw);

        $this->cleanup_expired_refresh_tokens($user_id);

        $this->_lava->db->raw("insert into {$this->refresh_token_table} (user_id, token, expires_at) VALUES (?, ?, ?)", [$user_id, $refresh_token_encrypted, date('Y-m-d H:i:s', $refresh_payload['exp'])]);

        return [
            'access_token' => $access_token,
            'refresh_token' => $refresh_token_raw,
            'expires_in' => 900
        ];
    }

    /**
     * refresh_access_token
     *
     * @param string $refresh_token
     * @return void
     */
    public function refresh_access_token($refresh_token)
    {
        $payload = $this->validate_jwt($refresh_token);
        if (!$payload || ($payload['type'] ?? '') !== 'refresh') {
            $this->respond_error('Invalid refresh token', 403);
        }

        $encrypted = $this->encrypt_token($refresh_token);
        $stmt = $this->_lava->db->raw("select * from {$this->refresh_token_table} WHERE token = ? LIMIT 1", [$encrypted]);
        $found = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$found || strtotime($found['expires_at']) < time()) {
            $this->respond_error('Refresh token expired or not found', 403);
        }

        $this->revoke_refresh_token($refresh_token);
        $new = $this->issue_tokens(['id' => $payload['sub']]);
        $this->respond([
            'message' => 'Token refreshed successfully',
            'tokens' => $new
        ]);
    }

    /**
     * revoke_refresh_token
     *
     * @param string $refresh_token
     * @return void
     */
    public function revoke_refresh_token($refresh_token)
    {
        $encrypted = $this->encrypt_token($refresh_token);
        $this->_lava->db->raw("delete from {$this->refresh_token_table} WHERE token = ?", [$encrypted]);
    }

    public function cleanup_expired_refresh_tokens($user_id)
    {
        $this->_lava->db->raw("delete from {$this->refresh_token_table} WHERE user_id = ? AND expires_at < NOW()", [$user_id]);
    }

    // --------------------------
    // Refresh Token Encryption
    // --------------------------
    /**
     * encrypt_token
     *
     * @param string $token
     * @return void
     */
    private function encrypt_token($token)
    {
        $key = hash('sha256', $this->refresh_token_key);
        $iv = substr(hash('sha256', 'static_iv'), 0, 16);
        return openssl_encrypt($token, 'AES-256-CBC', $key, 0, $iv);
    }

    /**
     * decrypt_token
     *
     * @param string $encrypted
     * @return void
     */
    public function decrypt_token($encrypted)
    {
        $key = hash('sha256', $this->refresh_token_key);
        $iv = substr(hash('sha256', 'static_iv'), 0, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }

    // --------------------------
    // Basic Auth Support
    // --------------------------
    /**
     * check_basic_auth
     *
     * @param string $valid_user
     * @param string $valid_pass
     * @return void
     */
    public function check_basic_auth($valid_user, $valid_pass)
    {
        $user = $_SERVER['PHP_AUTH_USER'] ?? '';
        $pass = $_SERVER['PHP_AUTH_PW'] ?? '';
        return ($user === $valid_user && $pass === $valid_pass);
    }

    /**
     * require_basic_auth
     *
     * @param string $valid_user
     * @param string $valid_pass
     * @return void
     */
    public function require_basic_auth($valid_user, $valid_pass)
    {
        if (!$this->check_basic_auth($valid_user, $valid_pass)) {
            header('WWW-Authenticate: Basic realm="Restricted"');
            $this->respond_error('Unauthorized', 401);
        }
    }
}