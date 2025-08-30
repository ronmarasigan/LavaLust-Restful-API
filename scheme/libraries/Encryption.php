<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');
/**
 * ------------------------------------------------------------------
 * LavaLust - an opensource lightweight PHP MVC Framework
 * ------------------------------------------------------------------
 *
 * MIT License
 *
 * Copyright (c) 2020 Ronald M. Marasigan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @package LavaLust
 * @author Ronald M. Marasigan <ronald.marasigan@yahoo.com>
 * @since Version 4
 * @link https://github.com/ronmarasigan/LavaLust
 * @license https://opensource.org/licenses/MIT MIT License
 */

/**
* ------------------------------------------------------
*  Encryption Config
* ------------------------------------------------------
 */
class Encryption {

    /**
     * Encryption Key
     *
     * @var string
     */
    private $encryption_key;

    /**
     * Cipher type
     *
     * @var string
     */
    private $method;

    public function __construct($method = 'aes-128-cbc') {
        if (empty(config_item('encryption_key'))) {
            throw new RuntimeException('Encryption key is empty. Please provide the key in your config.php file.');
        }
        $this->encryption_key = config_item('encryption_key');

        // Validate the provided encryption method
        if (!in_array(strtolower($method), openssl_get_cipher_methods())) {
            throw new RuntimeException("Invalid encryption method: $method");
        }

        $this->method = $method;
    }

    /**
     * Encrypt input value
     *
     * @param string $input
     * @return string
     */
    public function encrypt($input)
    {
        $iv_size = openssl_cipher_iv_length($this->method);
        $iv = openssl_random_pseudo_bytes($iv_size); // Generate a random IV

        if (stripos($this->method, 'gcm') !== false) {
            // GCM mode requires an authentication tag
            $tag = '';
            $encrypted = openssl_encrypt($input, $this->method, $this->encryption_key, OPENSSL_RAW_DATA, $iv, $tag);

            return base64_encode($iv . $tag . $encrypted); // Store IV + Tag + Encrypted Data
        }

        // Default CBC mode encryption
        $encrypted = openssl_encrypt($input, $this->method, $this->encryption_key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt input value
     *
     * @param string $input
     * @return string|false
     */
    public function decrypt($input)
    {
        $data = base64_decode($input);
        $iv_size = openssl_cipher_iv_length($this->method);
        $iv = substr($data, 0, $iv_size);
        $encrypted_data = substr($data, $iv_size);

        if (stripos($this->method, 'gcm') !== false) {
            // GCM mode requires extracting the authentication tag
            $tag_size = 16; // Usually 16 bytes
            $tag = substr($encrypted_data, 0, $tag_size);
            $encrypted_data = substr($encrypted_data, $tag_size);

            return openssl_decrypt($encrypted_data, $this->method, $this->encryption_key, OPENSSL_RAW_DATA, $iv, $tag);
        }

        return openssl_decrypt($encrypted_data, $this->method, $this->encryption_key, OPENSSL_RAW_DATA, $iv);
    }
}

