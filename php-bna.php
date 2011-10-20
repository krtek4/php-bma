<?php

require_once('classes/Authenticator.php');

if(count($argv) == 3) {
	$auth = new Authenticator($argv[1], $argv[2]);
} else if(count($argv) == 2) {
	$auth = new Authenticator();
	$auth->initialize($argv[1]);
} else {
	echo "usage: php ".$argv[0]." [region] | [serial secret]\r\n";
	die();
}

while(true) {
	$code = $auth->code();
	echo "key: $code\r\n";
	$wait = 1 + $auth->remainingtime() / 1000;
	echo 'waiting for '.$wait." sec\r\n\r\n";
	sleep($wait);
}
