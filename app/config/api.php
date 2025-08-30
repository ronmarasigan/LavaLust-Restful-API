<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

/*
|--------------------------------------------------------------------------
| Enable/Disable Migrations
|--------------------------------------------------------------------------
|
| Migrations are disabled by default for security reasons.
| You should enable migrations whenever you intend to do a schema migration
| and disable it back when you're done.
|
*/
$config['api_helper_enabled'] = TRUE;

/*
|--------------------------------------------------------------------------
| JWT Secret Token
|--------------------------------------------------------------------------
|
| Used for Securing endpoint
|
*/
$config['jwt_secret'] = 'abc123';

/*
|--------------------------------------------------------------------------
| Refresh Token
|--------------------------------------------------------------------------
|
| Used for Securing endpoint
|
*/
$config['refresh_token_key'] = 'abc123';

/*
|--------------------------------------------------------------------------
| Access-Control-Allow-Origin
|--------------------------------------------------------------------------
|
| Access-Control-Allow-Origin - change this to your domain if
| already deployed.
|
*/
$config['allow_origin'] = '*';

/*
|--------------------------------------------------------------------------
| Refresh Token Table
|--------------------------------------------------------------------------
|
| This is the name of the table that will store the Refresh Token.
|
*/
$config['refresh_token_table'] = 'refresh_tokens';
