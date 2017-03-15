<?php

namespace Kronos\Encrypt\KeyProvider;

use Aws\Kms\KmsClient;
use Kronos\Encrypt\KeyProvider\KMS\KeyDescription;

class KMS implements Adaptor {

	/**
	 * @var KmsClient
	 */
	private $client;

	/**
	 * @var KeyDescription
	 */
	private $key_description;

	private $decrypted_key = NULL;

	/**
	 * @param KmsClient $client
	 * @param KeyDescription $key_description
	 */
	public function __construct(KmsClient $client, KeyDescription $key_description) {
		$this->client = $client;
		$this->key_description = $key_description;
	}

	public function getKey() {
		if(!$this->decrypted_key) {
			$response = $this->client->decrypt([
				'CiphertextBlob' => $this->key_description->ciphertextBlob,
				//'EncryptionContext' => $this->key_description->context
			]);

			$this->decrypted_key = $response['Plaintext'];
		}

		return $this->decrypted_key;
	}

}