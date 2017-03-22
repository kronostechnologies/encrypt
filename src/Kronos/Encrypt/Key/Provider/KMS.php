<?php

namespace Kronos\Encrypt\Key\Provider;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Kronos\Encrypt\Key\Exception\FetchException;
use Kronos\Encrypt\Key\KMS\KeyDescription;

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

	/**
	 * Return KMS decrypted key
	 * @return string
	 * @throws FetchException
	 */
	public function getKey() {
		if(!$this->decrypted_key) {
			$options = [
				'CiphertextBlob' => $this->key_description->ciphertextBlob
			];

			$context = $this->key_description->getContextAsArray();
			if(!empty($context)) {
				$options['EncryptionContext'] = $context;
			}

			try {
				$response = $this->client->decrypt($options);
			}
			catch(KmsException $e) {
				throw new FetchException('Key decryption failed', 0, $e);
			}

			$this->decrypted_key = $response['Plaintext'];
		}

		return $this->decrypted_key;
	}

}