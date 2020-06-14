<?php

declare(strict_types=1);

namespace SAML2\XML\saml;

use DOMElement;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Exception\InvalidDOMElementException;
use SAML2\Exception\MissingElementException;
use SAML2\Exception\TooManyElementsException;
use SAML2\Utilities\Temporal;
use SAML2\Utils;
use SAML2\XML\ds\Signature;
use SAML2\XML\IdentifierTrait;
use SAML2\XML\SignedElementInterface;
use SAML2\XML\SignedElementTrait;
use SimpleSAML\Assert\Assert;

/**
 * Class representing a SAML 2 assertion.
 *
 * @package simplesamlphp/saml2
 */
class Assertion extends AbstractSamlElement implements SignedElementInterface
{
    use IdentifierTrait;
    use SignedElementTrait;

    /**
     * The identifier of this assertion.
     *
     * @var string
     */
    protected $id;

    /**
     * The issue timestamp of this assertion, as an UNIX timestamp.
     *
     * @var int
     */
    protected $issueInstant;

    /**
     * The issuer of this assertion.
     *
     * If the issuer's format is \SAML2\Constants::NAMEID_ENTITY, this property will just take the issuer's string
     * value.
     *
     * @var \SAML2\XML\saml\Issuer
     */
    protected $issuer;

    /**
     * The subject of this assertion
     *
     * @var \SAML2\XML\saml\Subject|null
     */
    protected $subject;

    /**
     * The statements made by this assertion.
     *
     * @var \SAML2\XML\saml\AbstractStatement[]
     */
    protected $statements = [];

    /**
     * The attributes, as an associative array, indexed by attribute name
     *
     * To ease handling, all attribute values are represented as an array of values, also for values with a multiplicity
     * of single. There are 5 possible variants of datatypes for the values: a string, an integer, an array, a
     * DOMNodeList or a SAML2\XML\saml\NameID object.
     *
     * If the attribute is an eduPersonTargetedID, the values will be SAML2\XML\saml\NameID objects.
     * If the attribute value has an type-definition (xsi:string or xsi:int), the values will be of that type.
     * If the attribute value contains a nested XML structure, the values will be a DOMNodeList
     * In all other cases the values are treated as strings
     *
     * **WARNING** a DOMNodeList cannot be serialized without data-loss and should be handled explicitly
     *
     * @var array multi-dimensional array of \DOMNodeList|\SAML2\XML\saml\NameID|string|int|array
     */
    protected $attributes = [];

    /**
     * The attributes values types as per http://www.w3.org/2001/XMLSchema definitions
     * the variable is as an associative array, indexed by attribute name
     *
     * when parsing assertion, the variable will be:
     * - <attribute name> => [<Value1's xs type>|null, <xs type Value2>|null, ...]
     * array will always have the same size of the array of values in $attributes for the same <attribute name>
     *
     * when generating assertion, the variable can be:
     * - null : backward compatibility
     * - <attribute name> => <xs type> : all values for the given attribute will have the same xs type
     * - <attribute name> => [<Value1's xs type>|null, <xs type Value2>|null, ...] : Nth value will have type of the
     *   Nth in the array
     *
     * @var array multi-dimensional array of array
     * @todo this property is now irrelevant, this is implemented in AttributeValue
     */
//    protected $attributesValueTypes = [];

    /**
     * The SubjectConfirmation elements of the Subject in the assertion.
     *
     * @var \SAML2\XML\saml\SubjectConfirmation[]
     */
    protected $SubjectConfirmation = [];

    /**
     * @var bool
     */
    protected $wasSignedAtConstruction = false;

    /**
     * @var \SAML2\XML\saml\Conditions|null
     */
    protected $conditions;


    /**
     * Assertion constructor.
     *
     * @param \SAML2\XML\saml\Issuer $issuer
     * @param string|null $id
     * @param int|null $issueInstant
     * @param \SAML2\XML\saml\Subject|null $subject
     * @param \SAML2\XML\saml\Conditions|null $conditions
     * @param \SAML2\XML\saml\AbstractStatement[] $statements
     */
    public function __construct(
        Issuer $issuer,
        ?string $id = null,
        ?int $issueInstant = null,
        ?Subject $subject = null,
        ?Conditions $conditions = null,
        array $statements = []
    ) {
        Assert::true(
            $subject || !empty($statements),
            "Either a <saml:Subject> or some statement must be present in a <saml:Assertion>"
        );
        $this->setIssuer($issuer);
        $this->setId($id);
        $this->setIssueInstant($issueInstant);
        $this->setSubject($subject);
        $this->setConditions($conditions);
        $this->setStatements($statements);
    }


    /**
     * Collect the value of the subject
     *
     * @return \SAML2\XML\saml\Subject
     */
    public function getSubject(): Subject
    {
        return $this->subject;
    }


    /**
     * Set the value of the subject-property
     *
     * @param \SAML2\XML\saml\Subject|null $subject
     *
     * @return void
     */
    protected function setSubject(?Subject $subject): void
    {
        $this->subject = $subject;
    }


    /**
     * Collect the value of the conditions-property
     *
     * @return \SAML2\XML\saml\Conditions|null
     */
    public function getConditions(): ?Conditions
    {
        return $this->conditions;
    }


    /**
     * Set the value of the conditions-property
     *
     * @param \SAML2\XML\saml\Conditions|null $conditions
     *
     * @return void
     */
    protected function setConditions(?Conditions $conditions): void
    {
        $this->conditions = $conditions;
    }


    /**
     * @return \SAML2\XML\saml\AttributeStatement[]
     */
    public function getAttributeStatements(): array
    {
        return array_filter($this->statements, function ($statement) {
            return $statement instanceof AttributeStatement;
        });
    }


    /**
     * @return \SAML2\XML\saml\AuthnStatement[]
     */
    public function getAuthnStatements(): array
    {
        return array_filter($this->statements, function ($statement) {
            return $statement instanceof AuthnStatement;
        });
    }


    /**
     * @return \SAML2\XML\saml\Statement[]
     */
    public function getStatements(): array
    {
        return array_filter($this->statements, function ($statement) {
            return $statement instanceof Statement;
        });
    }


    /**
     * Set the statements in this assertion
     *
     * @param \SAML2\XML\saml\AbstractStatement[] $statements
     */
    protected function setStatements(array $statements): void
    {
        Assert::allIsInstanceOf($statements, AbstractStatement::class);

        $this->statements = $statements;
    }


    /**
     * Parse attribute statements in assertion.
     *
     * @param \DOMElement $xml The XML element with the assertion.
     *
     * @return void
     * @throws \Exception
     */
//    private function parseAttributes(DOMElement $xml): void
//    {
//        $firstAttribute = true;
//        /** @var \DOMElement[] $attributes */
//        $attributes = Utils::xpQuery($xml, './saml_assertion:AttributeStatement/saml_assertion:Attribute');
//        foreach ($attributes as $attribute) {
//            if (!$attribute->hasAttribute('Name')) {
//                throw new Exception('Missing name on <saml:Attribute> element.');
//            }
//            $name = $attribute->getAttribute('Name');
//
//            if ($attribute->hasAttribute('NameFormat')) {
//                $nameFormat = $attribute->getAttribute('NameFormat');
//            } else {
//                $nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
//            }
//
//            if ($firstAttribute) {
//                $this->nameFormat = $nameFormat;
//                $firstAttribute = false;
//            } else {
//                if ($this->nameFormat !== $nameFormat) {
//                    $this->nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
//                }
//            }
//
//            if (!array_key_exists($name, $this->attributes)) {
//                $this->attributes[$name] = [];
//                $this->attributesValueTypes[$name] = [];
//            }
//
//            $this->parseAttributeValue($attribute, $name);
//        }
//    }


    /**
     * @param \DOMNode $attribute
     * @param string   $attributeName
     *
     * @return void
     * @todo all attribute-specific logic should probably be in Attribute::fromXML()
     */
//    private function parseAttributeValue(DOMNode $attribute, string $attributeName): void
//    {
//        /** @var \DOMElement[] $values */
//        $values = Utils::xpQuery($attribute, './saml_assertion:AttributeValue');
//
//        if ($attributeName === Constants::EPTI_URN_MACE || $attributeName === Constants::EPTI_URN_OID) {
//            foreach ($values as $index => $eptiAttributeValue) {
//                /** @var \DOMElement[] $eptiNameId */
//                $eptiNameId = Utils::xpQuery($eptiAttributeValue, './saml_assertion:NameID');
//
//                if (count($eptiNameId) === 1) {
//                    $this->attributes[$attributeName][] = NameID::fromXML($eptiNameId[0]);
//                } else {
//                    /* Fall back for legacy IdPs sending string value (e.g. SSP < 1.15) */
//                    Utils::getContainer()->getLogger()->warning(
//                        sprintf("Attribute %s (EPTI) value %d is not an XML NameId", $attributeName, $index)
//                    );
//                    $nameId = new NameID($eptiAttributeValue->textContent);
//                    $this->attributes[$attributeName][] = $nameId;
//                }
//            }
//
//            return;
//        }
//
//        foreach ($values as $value) {
//            $hasNonTextChildElements = false;
//            foreach ($value->childNodes as $childNode) {
//                /** @var \DOMNode $childNode */
//                if ($childNode->nodeType !== XML_TEXT_NODE) {
//                    $hasNonTextChildElements = true;
//                    break;
//                }
//            }
//
//            $type = $value->getAttribute('xsi:type');
//            if ($type === '') {
//                $type = null;
//            }
//            $this->attributesValueTypes[$attributeName][] = $type;
//
//            if ($hasNonTextChildElements) {
//                $this->attributes[$attributeName][] = $value->childNodes;
//                continue;
//            }
//
//            if ($type === 'xs:integer') {
//                $this->attributes[$attributeName][] = intval($value->textContent);
//            } else {
//                $this->attributes[$attributeName][] = trim($value->textContent);
//            }
//        }
//    }


    /**
     * Validate this assertion against a public key.
     *
     * If no signature was present on the assertion, we will return false.
     * Otherwise, true will be returned. An exception is thrown if the
     * signature validation fails.
     *
     * @param \RobRichards\XMLSecLibs\XMLSecurityKey $key The key we should check against.
     *
     * @return boolean        true if successful, false if it is unsigned.
     *
     * @throws \SimpleSAML\Assert\AssertionFailedException if assertions are false
     */
//    public function validate(XMLSecurityKey $key): bool
//    {
//        Assert::same($key->type, XMLSecurityKey::RSA_SHA256);
//
//        if ($this->signatureData === null) {
//            return false;
//        }
//
//        Utils::validateSignature($this->signatureData, $key);
//
//        return true;
//    }


    /**
     * Retrieve the identifier of this assertion.
     *
     * @return string The identifier of this assertion.
     */
    public function getId(): string
    {
        return $this->id;
    }


    /**
     * Set the identifier of this assertion.
     *
     * @param string|null $id The new identifier of this assertion.
     *
     * @return void
     */
    public function setId(?string $id): void
    {
        if ($id === null) {
            $id = Utils::getContainer()->generateId();
        }
        $this->id = $id;
    }


    /**
     * Retrieve the issue timestamp of this assertion.
     *
     * @return int The issue timestamp of this assertion, as an UNIX timestamp.
     */
    public function getIssueInstant(): int
    {
        return $this->issueInstant;
    }


    /**
     * Set the issue timestamp of this assertion.
     *
     * @param int|null $issueInstant The new issue timestamp of this assertion, as an UNIX timestamp.
     *
     * @return void
     */
    public function setIssueInstant(?int $issueInstant): void
    {
        if ($this->issueInstant === null) {
            $issueInstant = Temporal::getTime();
        }

        $this->issueInstant = $issueInstant;
    }


    /**
     * Retrieve the issuer if this assertion.
     *
     * @return \SAML2\XML\saml\Issuer The issuer of this assertion.
     */
    public function getIssuer(): Issuer
    {
        return $this->issuer;
    }


    /**
     * Set the issuer of this message.
     *
     * @param \SAML2\XML\saml\Issuer $issuer The new issuer of this assertion.
     *
     * @return void
     */
    public function setIssuer(Issuer $issuer): void
    {
        $this->issuer = $issuer;
    }


    /**
     * Decrypt the assertion attributes.
     *
     * @param \RobRichards\XMLSecLibs\XMLSecurityKey $key
     * @param array          $blacklist
     *
     * @return void
     * @throws \Exception
     * @todo initialize blacklist to something sensible, wherever it makes sense (not here)
     */
//    public function decryptAttributes(XMLSecurityKey $key, array $blacklist = []): void
//    {
//        if (!$this->hasEncryptedAttributes()) {
//            return;
//        }
//
//        $attributeStatements = [];
//        foreach ($this->statements as $key => $statement) {
//            if (!$statement instanceof AttributeStatement) {
//                continue;
//            }
//            $attributes = $statement->getAttributes();
//            foreach ($statement->getEncryptedAttributes() as $encryptedAttribute) {
//                $attributes[] = $encryptedAttribute->decrypt($key, $blacklist);
//            }
//            unset($this->statements[$key]);
//            $this->statements[] = new AttributeStatement($attributes);
//        }
//        /**
//         * @todo default attribute's nameformat to UNSPECIFIED?
//         */
//        $firstAttribute = true;
//        $attributes = $this->getEncryptedAttributes();
//        foreach ($attributes as $attributeEnc) {
//            /* Decrypt node <EncryptedAttribute> */
//            $attribute = Utils::decryptElement(
//                $attributeEnc->getElementsByTagName('EncryptedData')->item(0),
//                $key,
//                $blacklist
//            );
//
//            if (!$attribute->hasAttribute('Name')) {
//                throw new Exception('Missing name on <saml:Attribute> element.');
//            }
//            $name = $attribute->getAttribute('Name');
//
//            if ($attribute->hasAttribute('NameFormat')) {
//                $nameFormat = $attribute->getAttribute('NameFormat');
//            } else {
//                $nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
//            }
//
//            if ($firstAttribute) {
//                $this->nameFormat = $nameFormat;
//                $firstAttribute = false;
//            } else {
//                if ($this->nameFormat !== $nameFormat) {
//                    $this->nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
//                }
//            }
//
//            if (!array_key_exists($name, $this->attributes)) {
//                $this->attributes[$name] = [];
//            }
//
//            $this->parseAttributeValue($attribute, $name);
//        }
//    }


    /**
     * Retrieve $requiredEncAttributes if attributes will be send encrypted
     *
     * @return bool True to encrypt attributes in the assertion.
     */
//    public function getRequiredEncAttributes(): bool
//    {
//        return $this->requiredEncAttributes;
//    }


    /**
     * Set $requiredEncAttributes if attributes will be send encrypted
     *
     * @param bool $ea true to encrypt attributes in the assertion.
     *
     * @return void
     */
//    public function setRequiredEncAttributes(bool $ea): void
//    {
//        $this->requiredEncAttributes = $ea;
//    }


    /**
     * Retrieve the SubjectConfirmation elements we have in our Subject element.
     *
     * @return array Array of \SAML2\XML\saml\SubjectConfirmation elements.
     */
    public function getSubjectConfirmation(): array
    {
        return $this->SubjectConfirmation;
    }


    /**
     * Set the SubjectConfirmation elements that should be included in the assertion.
     *
     * @param array $SubjectConfirmation Array of \SAML2\XML\saml\SubjectConfirmation elements.
     *
     * @return void
     */
    public function setSubjectConfirmation(array $SubjectConfirmation): void
    {
        Assert::allIsInstanceOf($SubjectConfirmation, SubjectConfirmation::class);
        $this->SubjectConfirmation = $SubjectConfirmation;
    }


    /**
     * @return bool
     */
    public function wasSignedAtConstruction(): bool
    {
        return $this->wasSignedAtConstruction;
    }


    /**
     * Convert XML into an Assertion
     *
     * @param \DOMElement $xml The XML element we should load
     *
     * @return \SAML2\XML\saml\Assertion
     * @throws \SAML2\Exception\InvalidDOMElementException if the qualified name of the supplied element is wrong
     * @throws \Exception
     */
    public static function fromXML(DOMElement $xml): object
    {
        Assert::same($xml->localName, 'Assertion', InvalidDOMElementException::class);
        Assert::same($xml->namespaceURI, Assertion::NS , InvalidDOMElementException::class);
        Assert::same(self::getAttribute($xml, 'Version'), '2.0', 'Unsupported version: %s');

        $issueInstant = Utils::xsDateTimeToTimestamp(self::getAttribute($xml, 'IssueInstant'));

        $issuer = Issuer::getChildrenOfClass($xml);
        Assert::count($issuer, 1, 'Missing or more than one <saml:Issuer> in assertion.');

        $subject = Subject::getChildrenOfClass($xml);
        Assert::maxCount($subject, 1, 'More than one <saml:Subject> in <saml:Assertion>');

        $conditions = Conditions::getChildrenOfClass($xml);
        Assert::maxCount($conditions, 1, 'More than one <saml:Conditions> in <saml:Assertion>.');

        $signature = Signature::getChildrenOfClass($xml);
        Assert::maxCount($signature, 1, 'Only one <ds:Signature> element is allowed.');

        $authnStatement = AuthnStatement::getChildrenOfClass($xml);
        $attrStatement = AttributeStatement::getChildrenOfClass($xml);
        $statements = Statement::getChildrenOfClass($xml);

        $assertion = new self(
            array_pop($issuer),
            self::getAttribute($xml, 'ID'),
            $issueInstant,
            array_pop($subject),
            array_pop($conditions),
            array_merge($authnStatement, $attrStatement, $statements)
        );

        if (!empty($signature)) {
            $assertion->setSignature($signature[0]);
            $assertion->wasSignedAtConstruction = true;
        }

        return $assertion;
    }


    /**
     * Convert this assertion to an XML element.
     *
     * @param \DOMElement|null $parentElement The DOM node the assertion should be created in.
     *
     * @return \DOMElement This assertion.
     *
     * @throws \InvalidArgumentException if assertions are false
     * @throws \Exception
     */
    public function toXML(DOMElement $parentElement = null): DOMElement
    {
        $e = self::instantiateParentElement($parentElement);

        $e->setAttribute('Version', '2.0');
        $e->setAttribute('ID', $this->id);
        $e->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->issueInstant));

        $this->issuer->toXML($e);

        if ($this->subject !== null) {
            $this->subject->toXML($e);
        }

        if ($this->conditions !== null) {
            $this->conditions->toXML($e);
        }

        foreach ($this->statements as $statement) {
            $statement->toXML($e);
        }

        return $this->signElement($e);
    }


    /**
     * Add an AttributeStatement-node to the assertion.
     *
     * @param \DOMElement $root The assertion element we should add the subject to.
     *
     * @return void
     * @todo evaluate creation of AttributeValue and see if we need to specify types
     */
//    private function addAttributeStatement(DOMElement $root): void
//    {
//        if (empty($this->attributes)) {
//            return;
//        }
//
//        $document = $root->ownerDocument;
//
//        $attributeStatement = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeStatement');
//        $root->appendChild($attributeStatement);
//
//        foreach ($this->attributes as $name => $values) {
//            $attribute = $document->createElementNS(Constants::NS_SAML, 'saml:Attribute');
//            $attributeStatement->appendChild($attribute);
//            $attribute->setAttribute('Name', $name);
//
//            if ($this->nameFormat !== Constants::NAMEFORMAT_UNSPECIFIED) {
//                $attribute->setAttribute('NameFormat', $this->nameFormat);
//            }
//
//            // make sure eduPersonTargetedID can be handled properly as a NameID
//            if ($name === Constants::EPTI_URN_MACE || $name === Constants::EPTI_URN_OID) {
//                foreach ($values as $eptiValue) {
//                    $attributeValue = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeValue');
//                    $attribute->appendChild($attributeValue);
//                    if ($eptiValue instanceof NameID) {
//                        $eptiValue->toXML($attributeValue);
//                    } elseif ($eptiValue instanceof DOMNodeList) {
//                        /** @var \DOMElement $value */
//                        $value = $eptiValue->item(0);
//                        $node = $root->ownerDocument->importNode($value, true);
//                        $attributeValue->appendChild($node);
//                    } else {
//                        $attributeValue->textContent = $eptiValue;
//                    }
//                }
//
//                continue;
//            }
//
//            // get value type(s) for the current attribute
//            if (array_key_exists($name, $this->attributesValueTypes)) {
//                $valueTypes = $this->attributesValueTypes[$name];
//                if (is_array($valueTypes) && count($valueTypes) != count($values)) {
//                    throw new \Exception('Array of value types and array of values have different size for attribute '.
//                        var_export($name, true));
//                }
//            } else {
//                // if no type(s), default behaviour
//                $valueTypes = null;
//            }
//
//            $vidx = -1;
//            foreach ($values as $value) {
//                $vidx++;
//
//                // try to get type from current types
//                $type = null;
//                if (!is_null($valueTypes)) {
//                    if (is_array($valueTypes)) {
//                        $type = $valueTypes[$vidx];
//                    } else {
//                        $type = $valueTypes;
//                    }
//                }
//
//                // if no type get from types, use default behaviour
//                if (is_null($type)) {
//                    if (is_string($value)) {
//                        $type = 'xs:string';
//                    } elseif (is_int($value)) {
//                        $type = 'xs:integer';
//                    } else {
//                        $type = null;
//                    }
//                }
//
//                $attributeValue = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeValue');
//                $attribute->appendChild($attributeValue);
//                if ($type !== null) {
//                    $attributeValue->setAttributeNS(Constants::NS_XSI, 'xsi:type', $type);
//                }
//                if (is_null($value)) {
//                    $attributeValue->setAttributeNS(Constants::NS_XSI, 'xsi:nil', 'true');
//                }
//
//                if ($value instanceof \DOMNodeList) {
//                    foreach ($value as $v) {
//                        $node = $document->importNode($v, true);
//                        $attributeValue->appendChild($node);
//                    }
//                } else {
//                    $value = strval($value);
//                    $attributeValue->appendChild($document->createTextNode($value));
//                }
//            }
//        }
//    }


    /**
     * Add an EncryptedAttribute Statement-node to the assertion.
     *
     * @param \DOMElement $root The assertion element we should add the Encrypted Attribute Statement to.
     *
     * @return void
     *
     * @throws \InvalidArgumentException if assertions are false
     * @todo review functionality implemented here, and see if we need to move it somewhere else
     */
//    private function addEncryptedAttributeStatement(DOMElement $root): void
//    {
//        if ($this->getRequiredEncAttributes() === false) {
//            return;
//        }
//        Assert::notNull($this->encryptionKey);
//
//        $document = $root->ownerDocument;
//
//        $attributeStatement = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeStatement');
//        $root->appendChild($attributeStatement);
//
//        foreach ($this->attributes as $name => $values) {
//            $document2 = DOMDocumentFactory::create();
//            $attribute = $document2->createElementNS(Constants::NS_SAML, 'saml:Attribute');
//            $attribute->setAttribute('Name', $name);
//            $document2->appendChild($attribute);
//
//            if ($this->nameFormat !== Constants::NAMEFORMAT_UNSPECIFIED) {
//                $attribute->setAttribute('NameFormat', $this->getAttributeNameFormat());
//            }
//
//            foreach ($values as $value) {
//                if (is_string($value)) {
//                    $type = 'xs:string';
//                } elseif (is_int($value)) {
//                    $type = 'xs:integer';
//                } else {
//                    $type = null;
//                }
//
//                $attributeValue = $document2->createElementNS(Constants::NS_SAML, 'saml:AttributeValue');
//                $attribute->appendChild($attributeValue);
//                if ($type !== null) {
//                    $attributeValue->setAttributeNS(Constants::NS_XSI, 'xsi:type', $type);
//                }
//
//                if ($value instanceof DOMNodeList) {
//                    foreach ($value as $v) {
//                        $node = $document2->importNode($v, true);
//                        $attributeValue->appendChild($node);
//                    }
//                } else {
//                    $value = strval($value);
//                    $attributeValue->appendChild($document2->createTextNode($value));
//                }
//            }
//            /*Once the attribute nodes are built, the are encrypted*/
//            $EncAssert = new XMLSecEnc();
//            $EncAssert->setNode($document2->documentElement);
//            $EncAssert->type = 'http://www.w3.org/2001/04/xmlenc#Element';
//            /*
//             * Attributes are encrypted with a session key and this one with
//             * $EncryptionKey
//             */
//            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
//            $symmetricKey->generateSessionKey();
//            /** @psalm-suppress PossiblyNullArgument */
//            $EncAssert->encryptKey($this->encryptionKey, $symmetricKey);
//            /** @psalm-suppress UndefinedClass */
//            $EncrNode = $EncAssert->encryptNode($symmetricKey);
//
//            $EncAttribute = $document->createElementNS(Constants::NS_SAML, 'saml:EncryptedAttribute');
//            $attributeStatement->appendChild($EncAttribute);
//            /** @psalm-suppress InvalidArgument */
//            $n = $document->importNode($EncrNode, true);
//            $EncAttribute->appendChild($n);
//        }
//    }
}
