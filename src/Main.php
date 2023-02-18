<?php

declare(strict_types=1);

namespace zodiax\TCPShield;

use Exception;
use pocketmine\event\Listener;
use pocketmine\event\server\DataPacketReceiveEvent;
use pocketmine\network\AdvancedNetworkInterface;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\network\RawPacketHandler;
use pocketmine\plugin\PluginBase;
use zodiax\TCPShield\misc\ProxyProtocol;
use zodiax\TCPShield\misc\Utils;

class Main extends PluginBase implements Listener, RawPacketHandler{

	/** @var string[] */
	private array $realIPs = [];
	protected function onEnable() : void{
		$this->getServer()->getPluginManager()->registerEvents($this, $this);
		$this->getServer()->getNetwork()->registerRawPacketHandler($this);
	}

	public function getPattern() : string{
		return '/\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A/';
	}

	/**
	 * @throws Exception
	 */
	public function handle(AdvancedNetworkInterface $interface, string $address, int $port, string $packet) : bool{
		$header = ProxyProtocol::parseHeader($packet);
		if($header !== null && $header->getSourceAddress() !== "127.0.0.1" && $header->getTargetAddress() !== "127.0.0.1"){
			$this->realIPs["$address:$port"] = "{$header->getSourceAddress()}:{$header->getSourcePort()}";
		}
		return $header !== null;
	}

	/**
	 * @handleCancelled
	 * @priority LOWEST
	 */
	public function onDataPacketReceiveEvent(DataPacketReceiveEvent $event){
		$packet = $event->getPacket();
		if(!$packet instanceof LoginPacket){
			return;
		}
		$session = $event->getOrigin();
		if(!isset($this->realIPs[$address = "{$session->getIp()}:{$session->getPort()}"])){
			return;
		}
		$realAddress = explode(":", $this->realIPs[$address]);
		Utils::forceSetProps($session, "ip", $realAddress[0]);
		Utils::forceSetProps($session, "port", $realAddress[1]);
		unset($this->realIPs[$address]);
	}
}
