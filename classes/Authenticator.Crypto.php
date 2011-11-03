<?php

// Some crypto functions for Blizzard Authenticator
// RSA part based on http://stevish.com/rsa-encryption-in-pure-php

// This script is distributed under the terms of the GNU General Public License (GPL)
// See http://www.gnu.org/licenses/gpl.txt for license details

class Authenticator_Crypto {
	static private $rsa_mod = "104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097";
	static private $rsa_exp = '257';
	static private $keysize = 1024;

	static public function encrypt($text) {
		$text = self::bchexdec(bin2hex($text));
		$n = bcpowmod($text, self::$rsa_exp, self::$rsa_mod);
		$ret = '';
		while($n > 0) {
			$ret = chr(bcmod($n, 256)).$ret;
			$n = bcdiv($n, 256, 0);
		}
		return $ret;
	}

	static public function decrypt($code, $key) {
		$ret = '';
		for($i = 0; $i < strlen($code); ++$i) {
			$c = ord($code{$i});
			$k = ord($key{$i});
			$ret .= chr($c ^ $k);
		}
		return $ret;
	}

	static public function restore_code_from_char($restore) {
		for($i = 0; $i < 10; ++$i) {
			$c = ord($restore{$i});
			if($c > 47 && $c < 58)
				$c -= 48;
			else {
				$c -= 55;
				if($c > 72) --$c; // I
				if($c > 75) --$c; // L
				if($c > 78) --$c; // O
				if($c > 82) --$c; // S
			}
			$restore{$i} = chr($c);
		}
		return $restore;
	}

	static public function restore_code_to_char($data) {
		for($i = 0; $i < 10; ++$i) {
			$c = ord($data{$i}) & 0x1f;
			if($c < 10)
				$c += 48;
			else {
				$c += 55;
				if($c > 72) ++$c; // I
				if($c > 75) ++$c; // L
				if($c > 78) ++$c; // O
				if($c > 82) ++$c; // S
			}
			$data{$i} = chr($c);
		}
		return $data;
	}

	static private function bchexdec($hex) {
		$dec = 0;
		$len = strlen($hex);
		for ($i = 1; $i <= $len; $i++)
			$dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
		return $dec;
	}
}
