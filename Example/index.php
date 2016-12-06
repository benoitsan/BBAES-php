<?php

namespace AES\Example;

require __DIR__ . '/../vendor/autoload.php';

use AES\AES;

$password = 'Passwôrd';
$message = 'Messâge';
$salt = hash('MD5', 'Sält', true);
$iv = 'îv';

$html = sprintf('<div><strong>Message:</strong> %s</div>', $message);
$html .= sprintf('<div><strong>Password:</strong> %s</div>', $password);
$html .= sprintf('<div><strong>Salt:</strong> %s</div>', bin2hex($salt));

$html .= '<h2>Details</h2>';

$hash = AES::hashPassword($password, AES::KEY_SIZE_128);
$html .= sprintf('<div><strong>128 bits hashed key:</strong> %s</div>', bin2hex($hash));

$html .= nl2br("\n");

$hash = AES::hashPassword($password, AES::KEY_SIZE_256);
$html .= sprintf('<div><strong>256 bits hashed key:</strong> %s</div>', bin2hex($hash));

$html .= nl2br("\n");

$hash = AES::saltPassword($password, $salt, AES::KEY_SIZE_128, AES::PBKDF2_DEFAULT_ITERATIONS);
$html .= sprintf('<div><strong>128 bits salted key:</strong> %s</div>', bin2hex($hash));

$html .= nl2br("\n");

$hash = AES::saltPassword($password, $salt, AES::KEY_SIZE_192, AES::PBKDF2_DEFAULT_ITERATIONS);
$html .= sprintf('<div><strong>192 bits salted key:</strong> %s</div>', bin2hex($hash));

$html .= nl2br("\n");

$hash = AES::saltPassword($password, $salt, AES::KEY_SIZE_256, AES::PBKDF2_DEFAULT_ITERATIONS);
$html .= sprintf('<div><strong>256 bits salted key:</strong> %s</div>', bin2hex($hash));

$html .= nl2br("\n");

$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_128, AES::PBKDF2_DEFAULT_ITERATIONS);
$data = AES::encrypt($message, $key, $iv);
$html .= sprintf('<div><strong>128 bits: encryption:</strong> %s</div>', $data);

$html .= nl2br("\n");

$data = AES::decrypt($data, $key);
$html .= sprintf('<div><strong>128 bits: decryption:</strong> %s</div>', $data);

$html .= nl2br("\n");

$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_192, AES::PBKDF2_DEFAULT_ITERATIONS);
$data = AES::encrypt($message, $key, $iv);
$html .= sprintf('<div><strong>192 bits: encryption:</strong> %s</div>', $data);

$html .= nl2br("\n");

$data = AES::decrypt($data, $key);
$html .= sprintf('<div><strong>192 bits: decryption:</strong> %s</div>', $data);

$html .= nl2br("\n");

$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_256, AES::PBKDF2_DEFAULT_ITERATIONS);
$data = AES::encrypt($message, $key, $iv);
$html .= sprintf('<div><strong>256 bits: encryption:</strong> %s</div>', $data);

$html .= nl2br("\n");

$data = AES::decrypt($data, $key);
$html .= sprintf('<div><strong>256 bits: decryption:</strong> %s</div>', $data);

header( 'content-type: text/html; charset=utf-8' );
echo sprintf("<html><head><title>%s</title><style>body{margin:0;padding:30px;font:14px/2.0 menlo,Helvetica;}h1{margin:0;font-size:48px;font-weight:normal;line-height:48px;}strong{display:inline-block;width:200px;}</style></head><body>%s</body></html>", 'Example', $html);


