<?php

namespace benoitsan\AES\Tests;

use benoitsan\AES\AES;

class AESTest extends \PHPUnit_Framework_TestCase
{
	protected $password = '';
	
	public function testSalt()
	{
		$salt = AES::salt(10);
		$this->assertEquals(10, strlen($salt));

		$this->assertFalse(AES::salt(10) === AES::salt(10));
	}
	
	public function testKeyHashing()
	{
		$hash = AES::hashPassword('foo',AES::KEY_SIZE_128);
		$this->assertEquals(AES::KEY_SIZE_128, strlen($hash));
		
		$hash = AES::hashPassword('foo',AES::KEY_SIZE_256);
		$this->assertEquals(AES::KEY_SIZE_256, strlen($hash));
	}
	
	public function testPasswordSalting()
	{
		$hash = AES::saltPassword('password', 'salt', AES::KEY_SIZE_128);
		$this->assertEquals(AES::KEY_SIZE_128, strlen($hash));
		
		$hash = AES::saltPassword('password', 'salt', AES::KEY_SIZE_192);
		$this->assertEquals(AES::KEY_SIZE_192, strlen($hash));
		
		$hash = AES::saltPassword('password', 'salt', AES::KEY_SIZE_256);
		$this->assertEquals(AES::KEY_SIZE_256, strlen($hash));
		
		$this->assertTrue(AES::saltPassword('password', 'salt', AES::KEY_SIZE_256) === AES::saltPassword('password', 'salt', AES::KEY_SIZE_256));
		$this->assertFalse(AES::saltPassword('password1', 'salt', AES::KEY_SIZE_256) === AES::saltPassword('password2', 'salt', AES::KEY_SIZE_256));
		$this->assertFalse(AES::saltPassword('password', 'salt1', AES::KEY_SIZE_256) === AES::saltPassword('password', 'salt2', AES::KEY_SIZE_256));
	}
	
	public function testEncryption()
	{
		$message = 'message';
		$password = 'password';
		$salt = 'salt';
		
		$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_128);
		$encrypted = AES::encrypt($message, $key, null);
		$decrypted = AES::decrypt($encrypted, $key);
		$this->assertTrue($decrypted === $message);
		
		$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_192);
		$encrypted = AES::encrypt($message, $key, null);
		$decrypted = AES::decrypt($encrypted, $key);
		$this->assertTrue($decrypted === $message);
		
		$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_256);
		$encrypted = AES::encrypt($message, $key, null);
		$decrypted = AES::decrypt($encrypted, $key);
		$this->assertTrue($decrypted === $message);
	}
	
	public function testIV()
	{
		$message = 'message';
		$password = 'password';
		$salt = 'salt';
		
		$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_128);
		$encrypted1 = AES::encrypt($message, $key, null);
		$encrypted2 = AES::encrypt($message, $key, null);
		$this->assertFalse($encrypted1 === $encrypted2);
		
		$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_128);
		$encrypted1 = AES::encrypt($message, $key, 'iv');
		$encrypted2 = AES::encrypt($message, $key, 'iv');
		$this->assertTrue($encrypted1 === $encrypted2);
		
		$key = AES::saltPassword($password, $salt, AES::KEY_SIZE_128);
		$encrypted1 = AES::encrypt($message, $key, 'iv1');
		$encrypted2 = AES::encrypt($message, $key, 'iv2');
		$this->assertFalse($encrypted1 === $encrypted2);
	}
}
















