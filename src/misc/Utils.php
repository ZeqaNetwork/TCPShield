<?php

declare(strict_types=1);

namespace zodiax\TCPShield\misc;

use ReflectionClass;
use ReflectionException;

class Utils{
	public static function forceGetProps($object, string $propName) : mixed{
		try{
			$reflection = new ReflectionClass($object);
			$prop = $reflection->getProperty($propName);
			$prop->setAccessible(true);
			return $prop->getValue($object);
		}catch(ReflectionException $e){
			return null;
		}
	}

	public static function forceSetProps($object, string $propName, $value) : void{
		try{
			$reflection = new ReflectionClass($object);
			$prop = $reflection->getProperty($propName);
			$prop->setAccessible(true);
			$prop->setValue($object, $value);
		}catch(ReflectionException $e){
		}
	}

	public static function forceCallMethod($object, string $methodName, ...$args) : void{
		try{
			$reflection = new ReflectionClass($object);
			$method = $reflection->getMethod($methodName);
			$method->setAccessible(true);
			($method->getClosure($object))(...$args);
		}catch(ReflectionException $e){
		}
	}
}