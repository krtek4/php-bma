<?php

require_once('classes/Authenticator.php');

if(count($argv) == 3) {
	$auth = Authenticator::factory($argv[1], $argv[2]);
} else if(count($argv) == 2) {
	$auth = Authenticator::generate($argv[1]);
	echo "New Authenticator requested. Serial: ".$auth->serial()." Secret: ".$auth->secret()."\r\n\r\n";
} else {
	echo "usage: php ".$argv[0]." [region] | [serial secret]\r\n";
	die();
}

while(true) {
	$code = $auth->code();
	echo "key: $code\r\n";
	$wait = 1 + ($auth->waitingtime() - $auth->elapsedtime()) / 1000;
	echo 'waiting for '.$wait." sec\r\n\r\n";
	sleep($wait);
}
