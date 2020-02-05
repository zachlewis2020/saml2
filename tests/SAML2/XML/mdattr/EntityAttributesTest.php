<?php

declare(strict_types=1);

namespace SAML2\XML\mdattr;

use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\XML\Chunk;
use SAML2\XML\saml\Attribute;
use SAML2\XML\saml\AttributeValue;
use SAML2\XML\mdattr\EntityAttributes;
use SAML2\Utils;

/**
 * Class \SAML2\XML\mdattr\EntityAttributesTest
 */
final class EntityAttributesTest extends \PHPUnit\Framework\TestCase
{
    /** @var \DOMDocument */
    private $document;


    /**
     * @return void
     */
    public function setUp(): void
    {
        $this->document = DOMDocumentFactory::fromString(<<<XML
<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:simplesamlphp:v1:simplesamlphp" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">is</saml:AttributeValue>
    <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">really</saml:AttributeValue>
    <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">cool</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="foo" NameFormat="urn:simplesamlphp:v1">
    <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">bar</saml:AttributeValue>
  </saml:Attribute>
</mdattr:EntityAttributes>
XML
        );
    }


    /**
     * @return void
     */
    public function testMarshalling(): void
    {
        $attribute1 = new Attribute(
            'urn:simplesamlphp:v1:simplesamlphp',
            Constants::NAMEFORMAT_URI,
            null,
            [
                new AttributeValue('is'),
                new AttributeValue('really'),
                new AttributeValue('cool'),
            ]
        );

        $attribute2 = new Attribute(
            'foo',
            'urn:simplesamlphp:v1',
            null,
            [
                new AttributeValue('bar')
            ]
        );

        $entityAttributes = new EntityAttributes([$attribute1]);
        $entityAttributes->addChild($attribute2);

        $this->assertEquals($this->document->saveXML($this->document->documentElement), strval($entityAttributes));
    }


    /**
     * @return void
     */
    public function testUnmarshalling(): void
    {
        $entityAttributes = EntityAttributes::fromXML($this->document->documentElement);
        $this->assertCount(2, $entityAttributes->getChildren());

        $this->assertInstanceOf(Attribute::class, $entityAttributes->getChildren()[0]);
        $this->assertInstanceOf(Attribute::class, $entityAttributes->getChildren()[1]);
    }


    /**
     * @return void
     */
    public function testUnmarshallingAttributes(): void
    {
        $entityAttributes = EntityAttributes::fromXML($this->document->documentElement);
        $this->assertCount(2, $entityAttributes->getChildren());

        $this->assertEquals('urn:simplesamlphp:v1:simplesamlphp', $entityAttributes->getChildren()[0]->getName());
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', $entityAttributes->getChildren()[0]->getNameFormat());
        $this->assertCount(3, $entityAttributes->getChildren()[0]->getAttributeValues());
        $this->assertEquals('foo', $entityAttributes->getChildren()[1]->getName());
        $this->assertEquals('urn:simplesamlphp:v1', $entityAttributes->getChildren()[1]->getNameFormat());
        $this->assertCount(1, $entityAttributes->getChildren()[1]->getAttributeValues());
    }


    /**
     * Test serialization / unserialization
     */
    public function testSerialization(): void
    {
        $this->assertEquals(
            $this->document->saveXML($this->document->documentElement),
            strval(unserialize(serialize(EntityAttributes::fromXML($this->document->documentElement))))
        );
    }
}
