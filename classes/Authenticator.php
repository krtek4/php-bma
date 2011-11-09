<?php

require_once('Authenticator.Crypto.php');

class AuthenticatorException extends Exception { }
class NotImplementedAuthenticatorException extends AuthenticatorException { }

class Authenticator {
	// <editor-fold defaultstate="collapsed" desc="static variables">

	/**
	 * @var string format for the Battle.Net servers, %s must be replaced by the region
	 */
	static private $server = 'm.%s.mobileservice.blizzard.com';

	/**
	 * @var string URI used for initialization
	 */
	static private $initialize_uri = "/enrollment/enroll.htm";
	/**
	 * @var string URI used for synchronization
	 */
	static private $synchronize_uri = "/enrollment/time.htm";
	/**
	 * @var string URI used for restoring a device
	 */
	static private $restore_uri = "/enrollment/initiatePaperRestore.htm";
	/**
	 * @var string URI used for validate the restoriation of a device
	 */
	static private $restore_validate_uri = "/enrollment/validatePaperRestore.htm";

	/**
	 * @var array array of accepted region string
	 */
	static private $accepted_region = array('EU', 'US');
	/**
	 * @var int time between two cycles in milliseconds
	 */
	static private $waitingtime = 30000;

	const GENERATE_SIZE = 45;
	const SYNC_SIZE = 8;
	const RESTORE_CHALLENGE_SIZE = 32;
	const RESTORE_VALIDATE_SIZE = 20;

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="variables">

	/**
	 * @var string 2 characters code of the current region.
	 */
	private $region = null;
	/**
	 * @var int delta between the local time and server time in milliseconds.
	 */
	private $sync = null;
	/**
	 * @var string Authenticator serial with the format 'XX-YYYY-YYYY-YYYY'
	 */
	private $serial = null;
	/**
	 * @var string 40 charactes long secret key composed of hexadecimal values
	 */
	private $secret = null;

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="constructor (private)">

	/**
	 * Create a new Authenticator. If the $secret is null, we assume that
	 * we want to generate a new one and thus $serial is in fact the region
	 * to use.
	 * @param string $serial The serial, same format as serial()
	 *						OR the region, same format as region()
	 * @param string $secret The secret key, same format as secret() (optional)
	 */
	private function __construct($serial, $secret = null) {
		if(is_null($secret)) {
			$this->set_region($serial);
		} else {
			$this->set_serial($serial);
			$this->set_secret($secret);
		}
	}

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="Authenticator factories">

	/**
	 * Create a new Authenticator freshly generated for the given region.
	 * @param string $region 2 characters region code.
	 * @return Authenticator the requested Authenticator
	 */
	static public function generate($region) {
		$authenticator = new Authenticator($region);
		$authenticator->initialize();
		return $authenticator;
	}

	/**
	 * Create a new Authenticator based on a given restore code
	 * provided by another device and its serial.
	 * @param string $serial The serial, same format as serial().
	 * @param string $restore_code 10 characters restore code
	 * @return Authenticator the requested Authenticator
	 */
	static public function restore($serial, $restore_code) {
		$authenticator = new Authenticator($serial, 'tempsecret');
		$authenticator->do_restore($restore_code);
		return $authenticator;
	}

	/**
	 * Create a new Authenticator with the given information.
	 * (@see serial(), @see secret())
	 * @param string $serial The serial, same format as serial().
	 * @param string $secret The secret key, same format as secret().
	 * @param int $sync sync time in milliseconds (optionnal)
	 * @return Authenticator the requested Authenticator
	 */
	static public function factory($serial, $secret, $sync = null) {
		$authenticator = new Authenticator($serial, $secret);
		if(! is_null($sync))
			$authenticator->set_sync ($sync);
		return $authenticator;
	}

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="public getters">

	/**
	 * The tow character code representing region of the authenticator
	 * @return string the region
	 */
	public function region() {
		if(is_null($this->region))
			throw new AuthenticatorException('Region must be set.');
		return $this->region;
	}

	/**
	 * Server time in milliseconds calculated with the help of the
	 * sync value received from the server.
	 * @return int server time in milliseconds
	 */
	public function servertime() {
		if(is_null($this->sync))
			$this->synchronize();
		return (int) (microtime(true) * 1000) + $this->sync;
	}

	/**
	 * The waiting in milliseconds time between each new code.
	 * @return int cycle time in milliseconds
	 */
	public function waitingtime() {
		return self::$waitingtime;
	}

	/**
	 * The elapsed time in milliseconds since the beginning of the
	 * last code cycle. The remaining waiting time can be computer
	 * by subtracting this to the cycle time (@see waitingtime()).
	 * @return int elapsed time in milliseconds
	 */
	public function elapsedtime() {
		return ($this->servertime() % $this->waitingtime());
	}

	/**
	 * The serial of the authenticator with the following format :
	 * 'XX-YYYY-YYYY-YYYY' where XX is the two character code of the
	 * region and Ys are numbers.
	 * @return string the serial
	 */
	public function serial() {
		if(is_null($this->serial))
			throw new AuthenticatorException('Unable to find a valid serial');
		return $this->serial;
	}

	/**
	 * The serial of the authenticator with the following format :
	 * 'XXYYYYYYYYYYYY' where XX is the two character code of the
	 * region and Ys are numbers.
	 * @return string the serial
	 */
	public function plain_serial() {
		return strtoupper(str_replace('-', '', $this->serial()));
	}

	/**
	 * The secret key of the authenticator as a 40 characters string composed
	 * of hexadecimal values.
	 * @return string the secret key
	 */
	public function secret() {
		if(is_null($this->secret))
			throw new AuthenticatorException('Unable to find the secret key');
		return $this->secret;
	}

	/**
	 * The 10 characters restore code returned by blizzard to allow restoring
	 * this particular authenticator on another device.
	 * @return string the restore code
	 */
	public function restore_code() {
		$serial = $this->plain_serial();
		$secret = pack('H*', $this->secret());
		// take the 10 last bytes of the digest of our data
		$data = substr(sha1($serial.$secret, true), -10);
		return Authenticator_Crypto::restore_code_to_char($data);
	}

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="public setters">

	/**
	 * Set the synchronization needed with the Battle.Net server related
	 * to this Authenticator.
	 * @param int $sync delta between current clock and server in milliseconds
	 */
	public function set_sync($sync) {
		$this->sync = $sync;
	}

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="private methods">

	/**
	 * Set the synchronization with data received from the server.
	 * Transform the data and then call set_sync().
	 * @param mixed $server_time binary data received from the server
	 */
	private function _set_sync($server_time) {
		$server_time = hexdec(bin2hex($server_time));
		$current_time = (int) (microtime(true) * 1000);
		$this->set_sync($server_time - $current_time);
	}


	/**
	 * Set the serial and the region with the two first characters
	 * @param string $serial format 'XX-YYYY-YYYY-YYYY'
	 */
	private function set_serial($serial) {
		$this->set_region(substr($serial, 0, 2));
		$this->serial = $serial;
	}

	private function set_region($region) {
		$region = strtoupper($region);
		if(! in_array($region, self::$accepted_region))
			throw new AuthenticatorException('Invalid region provided : '.$region.'.');
		$this->region = $region;
	}

	/**
	 * Set the secret key. Transform the data and then call set_secret().
	 * @param string $secret binary data from the server
	 */
	private function _set_secret($secret) {
		$this->set_secret(bin2hex($secret));
	}

	/**
	 * Set the secret key
	 * @param string $secret 40 hexadecimal values
	 */
	private function set_secret($secret) {
		$this->secret = $secret;
	}

	/**
	 * Return the server to use based on the current region.
	 * @return string The server address
	 */
	private function server() {
		return sprintf(self::$server, strtolower($this->region()));
	}

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="communications">

	/**
	 * Send data the the server related to the current region.
	 * @param string $uri the uri to use
	 * @param string $data the data
	 * @return string server response
	 */
	private function send($uri, $response_size, $data = null) {
		$host = $this->server();
		$method = is_null($data) ? 'GET' : 'POST';
		$data = is_null($data) ? '' : $data;

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
			throw new AuthenticatorException('Connection failed : ['.$errno.'] '.$errstr);
		fclose($http);

		$result = explode("\r\n\r\n", $result, 2);

		preg_match('/\d\d\d/', $result[0], $matches);
		if(! isset($matches[0]) || $matches[0] != 200)
			throw new AuthenticatorException('Invalid HTTP status code : '.$matches[0].'.');

		if(strlen($result[1]) != $response_size)
			throw new AuthenticatorException('Invalid response data size. Received '.strlen($result[1]).' bytes instead of '.$response_size.'.');

		return $result[1];
	}

	private function create_key($size) {
		return substr(sha1(rand()), 0, $size);
	}

	/**
	 * Generate a new authenticator for the current region.
	 */
	private function initialize() {
		$f_code = chr(1);
		$this->region();
		$enc_key = $this->create_key(37);
		$model = str_pad('PHP_BMA', 16, chr(0), STR_PAD_RIGHT);

		$data = $f_code.$enc_key.$this->region().$model;
		$response = $this->send(self::$initialize_uri, self::GENERATE_SIZE, $this->encrypt($data));
		$data = $this->decrypt(substr($response, 8), $enc_key);

		$this->_set_sync(substr($response, 0, 8));
		$this->_set_secret(substr($data, 0, 20));
		$this->set_serial(substr($data, 20));
	}

	/*
	 * restore the authenticator with the given code. The serial
	 * must already been set.
	 * @param string $restore_code 10 characters restore code
	 */
	private function do_restore($restore_code) {
		$serial = $this->plain_serial();
		$challenge = $this->send(self::$restore_uri, self::RESTORE_CHALLENGE_SIZE, $serial);

		$restore_code = Authenticator_Crypto::restore_code_from_char(strtoupper($restore_code));
		$mac = hash_hmac('sha1', $serial.$challenge, $restore_code, true);
		$enc_key = $this->create_key(20);
		$data = $serial.$this->encrypt($mac.$enc_key);
		$response = $this->send(self::$restore_validate_uri, self::RESTORE_VALIDATE_SIZE, $data);

		$data = $this->decrypt($response, $enc_key);
		$this->_set_secret($data);
		$this->synchronize();
	}

	/**
	 * Request the actual server time to the related Battle.Net server and set
	 * the synchronization data accordingly via _set_sync().
	 */
	private function synchronize() {
		$response = $this->send(self::$synchronize_uri, self::SYNC_SIZE);
		$this->_set_sync($response);
	}

	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="cryptography">

	/**
	 * Encrypth the data with the help of the Authenticator_Crypto class.
	 * @param string $data the data
	 * @return string encrypted data
	 */
	private function encrypt($data) {
		return Authenticator_Crypto::encrypt($data);
	}

	/**
	 * Decrypt the data received from the server with the given key with the
	 * help of the Authenticator_Crypto class.
	 * @param string $data received data
	 * @param string $key key
	 * @return string decrypted data.
	 */
	private function decrypt($data, $key) {
		return Authenticator_Crypto::decrypt($data, $key);
	}

	/**
	 * Computing the current Authenticator code.
	 * @return string 8 characters long Authenticator code.
	 */
	public function code() {
		// transform the secret key to binary data
		$secret = pack('H*', $this->secret());
		// compute the cycle number
		$time = (int) ($this->servertime() / $this->waitingtime());
		// convert the cycle to a 8 bytes unsigned long big endian order
		$cycle = pack('N*', 0, $time);
		// calculate HMAC-SHA1 from secret key and cycle
		$mac = hash_hmac('sha1', $cycle, $secret);
		// determine which 4 bytes of the MAC are taken as the current code
		// last 4 bit of the MAC points to the starting byte
		$start = hexdec($mac{39}) * 2;
		// select the byte at starting position and the following 3 bytes
		$mac_part = substr($mac, $start, 8);
		$code = hexdec($mac_part) & 0x7fffffff;
		// use the lowest 8 decimal digits from the selected integer as the
		// current authenticator code
		return str_pad($code % 100000000, 8, '0', STR_PAD_LEFT);
	}

	// </editor-fold>
}

?>
