<?php

namespace benoitsan\AES;

// The class uses the AES128 algorithm in CBC mode with PKCS#7 padding (128 means the IV has a fixed size of 128-bit).
//
// Note about MCRYPT_RIJNDAEL_128 
// AES is a variant of Rijndael which has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
// To be AES compliant, always choose MCRYPT_RIJNDAEL_128.
// More infos: (http://www.chilkatsoft.com/p/php_aes.txt)
	
class AES
{
	/**
     * AES Key sizes
     *
     * @var const
     */
	const KEY_SIZE_128 = 16;
	const KEY_SIZE_192 = 24;
	const KEY_SIZE_256 = 32;
	
	/**
	 * Recommended salt length.
	 *
	 * @var const
	 */	
	const SALT_DEFAULT_SIZE = 16;
	
	/**
	 * Recommended number of iterations for PBKDF2 
	 *
	 * @var const
	 */
	const PBKDF2_DEFAULT_ITERATIONS = 10000;
	
	/**
	 * The initialization vector length in bytes 
	 *
	 * @var const
	 */
	const IV_SIZE = 16;
	
	/**
     * Generate a random salt.
     *
     * @param $length Salt length in bytes.
     * @return string
     */
	public static function salt($length = self::SALT_DEFAULT_SIZE)
	{
		$salt = mcrypt_create_iv($length, self::randomizer());

		return $salt;
	}
	
	/**
	 * Stretchs the key to a given size. 
	 *
	 * @param $password The password to hash.
	 * @param $keySize The key size in bytes.
	 * @return string
	 */
	public static function hashPassword($password, $keySize = self::KEY_SIZE_256)
 	{
 		if ($keySize === self::KEY_SIZE_128) {
 			$hashFunction = 'MD5';
 		}
 		else if ($keySize === self::KEY_SIZE_256) {
 			$hashFunction = 'SHA256';
 		}
 		else {
 			throw new \InvalidArgumentException('The key size is not compatible.');
 		}
 		
 		return hash($hashFunction, $password, true);
 	}

	/**
	 * Strengthen the password into a cryptographic key.
	 *
	 * @param $password The password to salt.
	 * @param $salt The salt to use to tangle the password.
	 * @param $keySize The key size in bytes.
	 * @param $iterations Work factor.
	 * @return string
	 */
	public static function saltPassword($password, $salt, $keySize = self::KEY_SIZE_256, $iterations = self::PBKDF2_DEFAULT_ITERATIONS) //test: http://anandam.name/pbkdf2/
	{
		return self::PBKDF2Hash($password, $salt, $keySize, $iterations);
	}
	
	/**
	 * Encrypts a string and returns the encrypted data as a base 64 encoded string.
	 *
	 * @param $string The string to encrypt.
	 * @param $key The key used for the encryption.
	 * @param $iv The initialization vector. It must have a fixed size of 16 bytes.
	 * @return string
	 */	
	public static function encrypt($string, $key, $iv = null) 
	{
	    if ($iv === null) {
	    	$iv = mcrypt_create_iv(self::IV_SIZE, self::randomizer());
	    }
	    else {
	    	$iv = hash('MD5', $iv, true);
	    }
	    
	    /*
	    echo("data " . bin2hex($string)); echo("<br/>");
	    echo("key" . bin2hex($key)); echo("<br/>");
	    echo("iv " . bin2hex($iv));
		*/
		
		$pad = self::IV_SIZE - (strlen($string) % self::IV_SIZE);
		$paddedData = $string . str_repeat(chr($pad), $pad);
				
		$encryptedData = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $paddedData, MCRYPT_MODE_CBC, $iv);
		
		return base64_encode($iv . $encryptedData);
	}
	
	/**
	 * Decrypts a base 64 encoded string and returns the decrypted string.
	 *
	 * @param $string The string to encrypt.
	 * @param $key The key used for the encryption.
	 * @return string
	 */	
	public static function decrypt($string, $key)
	{
		$data = base64_decode($string);
		
		$iv = substr($data, 0, self::IV_SIZE);
		$data = substr($data, self::IV_SIZE);

		$decryptedData = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);

		$pad = ord($decryptedData[($length = strlen($decryptedData)) - 1]);
		if ($pad and $pad < self::IV_SIZE) {
			$unpadData = substr($decryptedData, 0, $length - $pad);
		}
		else {
			$unpadData = $decryptedData;
		}
		return $unpadData;
	}
	
	
	protected static function randomizer()
	{
		if (defined('MCRYPT_DEV_URANDOM')) {
			return MCRYPT_DEV_URANDOM;
		}
		elseif (defined('MCRYPT_DEV_RANDOM')){
			return MCRYPT_DEV_RANDOM;
		}
		else {
			mt_srand();
			return MCRYPT_RAND;
		}
	}
		
	protected static function PBKDF2Hash($password, $salt, $length, $iterations) //PBKDF2-HMAC-SHA1
	{
		$config = array(
			'hash_type'     => 'sha1',
			'hash_size'     => 20,
			'iterations'    => $iterations,
			'output_length' => $length,
		);

		$password = utf8_decode($password); 

		$block_count = ceil($config['output_length'] / $config['hash_size']);
		$output = '';

		for ($i = 1; $i <= $block_count; $i++)
		{
			$ib = $block = hash_hmac($config['hash_type'], $salt.pack('N', $i), $password, TRUE);

			for ($j = 1; $j < $config['iterations']; $j++)
			{
				$block = hash_hmac($config['hash_type'], $block, $password, TRUE);
				$ib ^= $block;
			}

			$output .= $ib;
		}

		return substr($output, 0, $config['output_length']);
	}
}
