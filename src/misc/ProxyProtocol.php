<?php

declare(strict_types=1);

namespace zodiax\TCPShield\misc;

use Exception;
use UnexpectedValueException;

class ProxyProtocol{

	const CMD_LOCAL = 0;
	const CMD_PROXY = 1;

	const UNSPECIFIED_PROTOCOL = "\x00";
	const TCP4 = "\x11";
	const UDP4 = "\x12";
	const TCP6 = "\x21";
	const UDP6 = "\x22";
	const USTREAM = "\x31";
	const USOCK = "\x32";

	const LENGTHS = [
		self::TCP4 => 12,
		self::UDP4 => 12,
		self::TCP6 => 36,
		self::UDP6 => 36,
		self::USTREAM => 216,
		self::USOCK => 216,
	];

	const SIGNATURES = [
		1 => "PROXY",
		2 => "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
	];

	private int $version = 2;
	private int $command = self::CMD_PROXY;
	private string $protocol = self::TCP4;

	/** @var string The address of the client. */
	private string $sourceAddress;

	/** @var string The address to which the client connected. */
	private string $targetAddress;

	/** @var int The port of the client */
	private int $sourcePort;

	/** @var int The port to which the client connected. */
	private int $targetPort;

	/**
	 * Returns the version command of the header.
	 *
	 * @return string|false
	 */
	private function getVersionCommand() : string|false{
		if($this->version == 2){
			return chr(($this->version << 4) + $this->command);
		}
		return false;
	}

	/**
	 * Returns the protocol of the header.
	 *
	 * @return string
	 */
	private function getProtocol() : string{
		if($this->version == 2){
			return $this->protocol;
		}else{
			return array_flip((new \ReflectionClass($this))->getConstants())[$this->protocol];
		}
	}

	/**
	 * Returns the length of the address base on header's protocol.
	 *
	 * @return string|false
	 */
	private function getAddressLength() : string|false{
		if($this->version == 2){
			return pack('n', self::LENGTHS[$this->protocol]);
		}
		return false;
	}

	/**
	 * Returns the full addresses of the header.
	 *
	 * @return string
	 * @throws Exception
	 */
	private function getAddresses() : string{
		return self::encodeAddress($this->version, $this->sourceAddress, $this->protocol) . ($this->version == 1 ? " " : "") . self::encodeAddress($this->version, $this->targetAddress, $this->protocol);
	}

	/**
	 * Returns the full ports of the header.
	 *
	 * @return string
	 * @throws Exception
	 */
	private function getPorts() : string{
		return self::encodePort($this->version, $this->sourcePort, $this->protocol) . ($this->version == 1 ? " " : "") . self::encodePort($this->version, $this->targetPort, $this->protocol);
	}

	/**
	 * Returns the signature of the header.
	 *
	 * @return string
	 */
	private function getSignature() : string{
		return self::SIGNATURES[$this->version];
	}

	/**
	 * Returns the source address of the header.
	 *
	 * @return string
	 */
	public function getSourceAddress() : string{
		return $this->sourceAddress;
	}

	/**
	 * Returns the target address of the header.
	 *
	 * @return string
	 */
	public function getTargetAddress() : string{
		return $this->targetAddress;
	}

	/**
	 * Returns the source port of the header.
	 *
	 * @return int
	 */
	public function getSourcePort() : int{
		return $this->sourcePort;
	}

	/**
	 * Returns the target port of the header.
	 *
	 * @return int
	 */
	public function getTargetPort() : int{
		return $this->targetPort;
	}

	/**
	 * Constructs the header by concatenating all relevant fields.
	 *
	 * @return string
	 * @throws Exception
	 */
	private function constructProxyHeader() : string{
		return implode($this->version == 1 ? "\x20" : "", array_filter([
			$this->getSignature(),
			$this->getVersionCommand(),
			$this->getProtocol(),
			$this->getAddressLength(),
			$this->getAddresses(),
			$this->getPorts(),
			$this->version == 1 ? "\r\n" : null
		]));
	}

	/**
	 * Parse the given buffer and return the proxy protocol header if found.
	 *
	 * @param string $buffer
	 *
	 * @return ProxyProtocol|null
	 * @throws Exception
	 */
	public static function parseHeader(string &$buffer) : ?ProxyProtocol{
		foreach(self::SIGNATURES as $version => $signature){
			if(strncmp($buffer, $signature, strlen($signature)) === 0){
				if($version === 1){
					$result = self::parseVersion1($buffer);
					break;
				}elseif($version === 2){
					$result = self::parseVersion2($buffer);
					break;
				}
			}
		}
		if(isset($result)){
			$constructed = $result->constructProxyHeader();
			if(strncmp($constructed, $buffer, strlen($constructed)) === 0){
				$buffer = substr($buffer, strlen($constructed));
				return $result;
			}
		}
		return null;
	}

	/**
	 * Parse the given buffer and return the proxy protocol v1.
	 *
	 * @param string $buffer
	 *
	 * @return ProxyProtocol|null
	 */
	private static function parseVersion1(string $buffer) : ?ProxyProtocol {
		$parts = explode("\x20", $buffer);
		if(count($parts) === 7 && $parts[6] === "\r\n"){
			$result = new self();
			$result->version = 1;
			$result->protocol = $parts[1];
			$result->sourceAddress = $parts[2];
			$result->targetAddress = $parts[3];
			$result->sourcePort = (int)$parts[4];
			$result->targetPort = (int)$parts[5];
			return $result;
		}
		return null;
	}

	/**
	 * Parse the given buffer and return the proxy protocol v2.
	 *
	 * @param string $buffer
	 *
	 * @return ProxyProtocol
	 * @throws Exception
	 */
	private static function parseVersion2(string $buffer) : ProxyProtocol{
		$version = ord(substr($buffer, 12, 1)) >> 4;
		$command = ord(substr($buffer, 12, 1)) % 16;
		$protocol = substr($buffer, 13, 1);

		$pos = 16;
		$sourceAddress = self::decodeAddress($version, substr($buffer, $pos, self::LENGTHS[$protocol] / 2 - 2), $protocol);
		$pos += self::LENGTHS[$protocol] / 2 - 2;
		$targetAddress = self::decodeAddress($version, substr($buffer, $pos, self::LENGTHS[$protocol] / 2 - 2), $protocol);
		$pos += self::LENGTHS[$protocol] / 2 - 2;
		$sourcePort = unpack('n', substr($buffer, $pos, 2))[1];
		$targetPort = unpack('n', substr($buffer, $pos + 2, 2))[1];

		$result = new self();
		$result->version = 2;
		$result->command = $command;
		$result->protocol = $protocol;
		$result->sourceAddress = $sourceAddress;
		$result->targetAddress = $targetAddress;
		$result->sourcePort = $sourcePort;
		$result->targetPort = $targetPort;
		return $result;
	}

	/**
	 * Returns the encoded address of the client.
	 *
	 * @param int    $version
	 * @param string $address
	 * @param string $protocol
	 *
	 * @return string|false
	 * @throws Exception
	 */
	private static function encodeAddress(int $version, string $address, string $protocol) : string|false{
		if($version == 1){
			return $address;
		}
		switch($protocol){
			case self::TCP4:
			case self::UDP4:
			case self::TCP6:
			case self::UDP6:
				$result = inet_pton($address);
				break;
			case self::USTREAM:
			case self::USOCK:
				throw new Exception("Unix socket not (yet) supported.");
			default:
				throw new UnexpectedValueException("Invalid protocol.");
		}
		return $result;
	}

	/**
	 * Returns the decoded address of the client.
	 *
	 * @param int    $version
	 * @param string $address
	 * @param string $protocol
	 *
	 * @return string|false
	 * @throws Exception
	 */
	private static function decodeAddress(int $version, string $address, string $protocol) : string|false{
		if($version == 1){
			return $address;
		}
		switch($protocol){
			case self::TCP4:
			case self::UDP4:
			case self::TCP6:
			case self::UDP6:
				$result = inet_ntop($address);
				break;
			case self::USTREAM:
			case self::USOCK:
				throw new Exception("Unix socket not (yet) supported.");
			default:
				throw new UnexpectedValueException("Invalid protocol.");

		}
		return $result;
	}

	/**
	 * Returns the encoded port of the client.
	 *
	 * @param int    $version
	 * @param int    $port
	 * @param string $protocol
	 *
	 * @return int|string|false
	 * @throws Exception
	 */
	private static function encodePort(int $version, int $port, string $protocol) : int|string|false{
		if($version == 1){
			return $port;
		}
		switch($protocol){
			case self::TCP4:
			case self::UDP4:
			case self::TCP6:
			case self::UDP6:
				$result = pack('n', $port);
				break;
			case self::USTREAM:
			case self::USOCK:
				throw new Exception("Unix socket not (yet) supported.");
			default:
				throw new UnexpectedValueException("Invalid protocol.");

		}
		return $result;
	}
}