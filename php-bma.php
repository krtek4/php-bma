<?php

require_once('classes/Authenticator.php');

function usage() {
	echo "Usage:\r\n";
	echo "\tphp php-bma.php new region\r\n";
	echo "\tphp php-bma.php generate serial secret\r\n";
	echo "\tphp php-bma.php restore serial restore_code\r\n\r\n";
}

$auth = false;
$method = isset($argv[1]) ? $argv[1] : null;
switch($method) {
	case "new":
		if (count($argv) == 3) {
			$auth = Authenticator::generate($argv[2]);
			$message = "New Authenticator requested";
		}
		break;
	case "generate":
		if (count($argv) == 4) {
			$auth = Authenticator::factory($argv[2], $argv[3]);
			$message = "Generate codes";
		}
		break;
	case "restore":
		if (count($argv) == 4) {
			$auth = Authenticator::restore($argv[2], $argv[3]);
			$message = "Restore requested"; 
		}
		break;
}

if($auth === false) {
	usage();
	exit(1);
}
echo $message." - Serial: ".$auth->serial()." Secret: ".$auth->secret()." Restore: " . $auth->restore_code() . "\r\n\r\n";

while(true) {
	$code = $auth->code();
	echo "key: $code\r\n";
	$wait = 1 + ($auth->waitingtime() - $auth->elapsedtime()) / 1000;
	echo 'waiting for '.$wait." sec\r\n\r\n";
	sleep($wait);
}

