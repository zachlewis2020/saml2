<?php

declare(strict_types=1);

namespace SAML2\XML;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\XML\xenc\EncryptedData;

/**
 * Interface for encrypted elements.
 *
 * @package simplesamlphp/saml2
 */
interface EncryptedElementInterface
{
    /**
     * Constructor for encrypted elements.
     *
     * @param \SAML2\XML\xenc\EncryptedData $encryptedData The EncryptedData object.
     * @param \SAML2\XML\xenc\EncryptedKey[] $encryptedKeys An array of zero or more EncryptedKey objects.
     */
    public function __construct(EncryptedData $encryptedData, array $encryptedKeys);


    /**
     * @param \RobRichards\XMLSecLibs\XMLSecurityKey $key The key we should use to decrypt the element.
     * @param string[] $blacklist List of blacklisted encryption algorithms.
     *
     * @return \SAML2\XML\AbstractXMLElement The decrypted element.
     */
    public function decrypt(XMLSecurityKey $key, array $blacklist = []): AbstractXMLElement;


    /**
     * Get the EncryptedData object.
     *
     * @return \SAML2\XML\xenc\EncryptedData
     */
    public function getEncryptedData(): EncryptedData;


    /**
     * Get the array of EncryptedKey objects
     *
     * @return \SAML2\XML\xenc\EncryptedKey[]
     */
    public function getEncryptedKeys(): array;
}
