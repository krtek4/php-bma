<?php

require_once('Authenticator.Crypto.php');

class AuthenticatorException extends Exception { }

class Authenticator {
	static private $server = 'm.%s.mobileservice.blizzard.com';
	static private $initialize_uri = "/enrollment/enroll.htm";
	static private $synchronize_uri = "/enrollment/time.htm";

	private $region = null;
	private $sync = null;
	private $serial = null;
	private $secret = null;

	public function __construct($serial = null, $secret = null) {
		if(! is_null($serial) && ! is_null($secret)) {
			$this->region = substr($serial, 0, 2);
			$this->secret = $secret;
			$this->serial = $serial;
		}
	}

	public function region() {
		if(is_null($this->region))
			throw new AuthenticatorException();
		return $this->region;
	}

	public function servertime() {
		if(is_null($this->sync))
			$this->synchronize();
		return (int) (microtime(true) * 1000) + $this->sync;
	}

	public function remainingtime() {
		return 30000 - ($this->servertime() % 30000);
	}

	private function set_sync($server_time) {
		$server_time = hexdec(bin2hex($server_time));
		$current_time = (int) (microtime(true) * 1000);
		$this->sync = $server_time - $current_time;
		var_dump($this->sync);
		var_dump($this->secret);
	}

	public function serial() {
		if(is_null($this->serial))
			throw new AuthenticatorException();
		return $this->serial;
	}

	private function set_serial($serial) {
		$this->serial = $serial;
	}

	public function secret() {
		if(is_null($this->secret))
			throw new AuthenticatorException();
		return $this->secret;
	}

	private function set_secret($secret) {
		$this->secret = bin2hex($secret);
	}

	private function server() {
		return sprintf(self::$server, strtolower($this->region()));
	}

	private function encrypt($data) {
		return Authenticator_Crypto::encrypt($data);
	}

	private function decrypt($data, $key) {
		return Authenticator_Crypto::decrypt($data, $key);
	}

	private function send($uri, $data = null) {
		$host = $this->server();
		$method = is_null($data) ? 'GET' : 'POST';
		$data = is_null($data) ? '' : $this->encrypt($data);

		$http = fsockopen($host, 80, $errno, $errstr, 2);
		if($http) {
			fputs($http, "$method $uri HTTP/1.1\r\n");
			fputs($http, "Host: $host\r\n");
			fputs($http, "Content-Type: application/octet-stream\r\n");
			fputs($http, "Content-length: ".strlen($data)."\r\n");
			fputs($http, "Connection: close\r\n\r\n");
			fputs($http, $data);

			$result = '';
			while(! feof($http))
				$result .= fgets($http, 128);
		} else
			throw new AuthenticatorException();
		fclose($http);

		$result = explode("\r\n\r\n", $result, 2);

		return $result[1];
	}

	public function initialize($region = 'US') {
		$f_code = chr(1);
		$enc_key = substr(sha1(rand()), 0, 37);
		$model = str_pad('PHP_BNA', 16, chr(0), STR_PAD_RIGHT);

		$data = $f_code.$enc_key.$region.$model;
		$response = $this->send(self::$initialize_uri, $data);

		$this->set_sync(substr($response, 0, 8));
		$data = $this->decrypt(substr($response, 8), $enc_key);
		$this->set_secret(substr($data, 0, 20));
		$this->set_serial(substr($data, 20));
	}

	public function synchronize() {
		$response = $this->send(self::$synchronize_uri);
		$this->set_sync($response);
	}

	public function code() {
		$secret = pack('H*', $this->secret());
		$time = (int) ($this->servertime() / 30000);
		// code interval as a 8 bytes unsigned long big endian order 
		$intervalNumber = pack('N*', 0, $time);
		// calculate HMAC-SHA1 from secret key and interval number
		$mac = hash_hmac('sha1', $intervalNumber, $secret);
		// determine which 4 bytes of the MAC are taken as the current code
		// last 4 bit of the MAC points to the starting byte
		$startPos = hexdec($mac{39}) * 2;
		// select the byte at starting position and the following 3 bytes
		$macPart = substr($mac, $startPos, 8);
		$selectedInt = hexdec($macPart);
		// use the lowest 8 decimal digits from the selected integer as the
		// current authenticator code
		return str_pad($selectedInt % 100000000, 8, '0', STR_PAD_LEFT);
	}
}

?>
