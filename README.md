# BBAES-PHP

BBAES-PHP is a lightweight AES Encryption Class with PHP 5.3+. 

BBAES-PHP uses the AES128 algorithm in CBC mode with PKCS#7 padding.

## Requirements

* PHP 5.3+
* PHPUnit to execute the tests (Optional).

## Installation

### With Composer

Install first [composer](http://getcomposer.org/). Create the following `composer.json` file and run the `composer install` command to install it.

``` json
{
    "require": {
        "benoitsan/aes": "*"
    }
}
```

``` php
<?
require 'vendor/autoload.php';

use benoitsan\AES;

printf(bin2hex(AES::saltPassword('password', AES::salt())));
```

### Without Composer

Save the file `AES.php` into your project path somewhere.

``` php
<?php
require 'path/to/AES.php';

use benoitsan\AES;

printf(bin2hex(AES::saltPassword('password', AES::salt())));
```

## Documentation

The file `AES.php` is documented. Have also a look at the demo and unit tests to see how to use the class.
     
## Creator

[Benoît Bourdon](https://github.com/benoitsan) ([@benoitsan](https://twitter.com/benoitsan)).

## License

BBAES-PHP is available under the MIT license. See the LICENSE file for more info.