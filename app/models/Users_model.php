<?php
    defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

    class Users_model extends Model {
        
        protected $table = 'users';
        protected $primary_key = 'id';
        protected $fillable = ['username', 'email', 'password', 'role'];

        public function __construct() {
            parent::__construct();
        }

        public function scopeByUserId($user_id) {
            return $this->filter(['id' => $user_id]);
        }

        public function scopeByUsername($username) {
            return $this->filter(['username' => $username]);
        }
    }
    ?>
    