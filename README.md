# BBAES-PHP

BBAES-PHP is a lightweight AES Encryption Class with PHP 5.6+. 

BBAES-PHP uses the AES128 algorithm in CBC mode with PKCS#7 padding.

## Requirements

* PHP 5.6+
* PHPUnit to execute the tests (Optional).

## Installation

Install first [composer](http://getcomposer.org/). Create the following `composer.json` file and run the `composer install` command to install it.

``` json
{
    "require": {
        "benoitsan/aes": "*"
    }
}
```

``` php
<?php
require 'vendor/autoload.php';

use \AES\AES;

$key = AES::saltPassword('password', AES::salt());
$encrypted = AES::encrypt('message', $key);
printf('encrypted: ' . $encrypted . "<br/>");
$decrypted = AES::decrypt($encrypted, $key);
printf('decrypted: ' . $decrypted);
```


## Documentation

The file `AES.php` is documented. Have also a look at the demo and unit tests to see how to use the class.
     
## Creator

[Benoît Bourdon](https://github.com/benoitsan) ([@benoitsan](https://twitter.com/benoitsan)).

## License

BBAES-PHP is available under the MIT license. See the LICENSE file for more info.