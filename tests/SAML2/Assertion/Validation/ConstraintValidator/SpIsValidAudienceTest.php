<?php

declare(strict_types=1);

namespace SAML2\Assertion\Validation\ConstraintValidator;

use Mockery;
use Mockery\Adapter\Phpunit\MockeryTestCase;
use SAML2\Assertion\Validation\ConstraintValidator\SpIsValidAudience;
use SAML2\Assertion\Validation\Result;
use SAML2\Configuration\ServiceProvider;
use SAML2\XML\saml\Assertion;
use SAML2\XML\saml\AudienceRestriction;
use SAML2\XML\saml\AuthnContext;
use SAML2\XML\saml\AuthnContextClassRef;
use SAML2\XML\saml\AuthnStatement;
use SAML2\XML\saml\Conditions;
use SAML2\XML\saml\Issuer;

/**
 * Because we're mocking a static call, we have to run it in separate processes so as to no contaminate the other
 * tests.
 */
class SpIsValidAudienceTest extends MockeryTestCase
{
    /**
     * @var \SAML2\XML\saml\AuthnStatement
     */
    private $authnStatement;

    /**
     * @var \SAML2\XML\saml\Conditions
     */
    private $conditions;

    /**
     * @var \SAML2\XML\saml\Isssuer
     */
    private $issuer;

    /**
     * @var \Mockery\MockInterface
     */
    private $serviceProvider;


    /**
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // Create an Issuer
        $this->issuer = new Issuer('testIssuer');

        // Create the conditions
        $this->conditions = new Conditions(
            null,
            null,
            [],
            [new AudienceRestriction(['audience1', 'audience2'])]
        );

        // Create the statements
        $this->authnStatement = new AuthnStatement(
            new AuthnContext(
                new AuthnContextClassRef('someAuthnContext'),
                null,
                null
            ),
            time()
        );

        $this->serviceProvider = Mockery::mock(ServiceProvider::class);
    }


    /**
     * @group assertion-validation
     * @test
     * @return void
     */
    public function when_no_valid_audiences_are_given_the_assertion_is_valid(): void
    {
        // Create an assertion
        $assertion = new Assertion($this->issuer, null, null, null, null, [$this->authnStatement]);

        $this->serviceProvider->shouldReceive('getEntityId')->andReturn('entityId');

        $validator = new SpIsValidAudience();
        $validator->setServiceProvider($this->serviceProvider);
        $result    = new Result();

        $validator->validate($assertion, $result);

        $this->assertTrue($result->isValid());
    }


    /**
     * @group assertion-validation
     * @test
     * @return void
     */
    public function if_the_sp_entity_id_is_not_in_the_valid_audiences_the_assertion_is_invalid(): void
    {
        // Create an assertion
        $assertion = new Assertion($this->issuer, null, null, null, $this->conditions, [$this->authnStatement]);

        $this->serviceProvider->shouldReceive('getEntityId')->andReturn('anotherEntityId');

        $validator = new SpIsValidAudience();
        $validator->setServiceProvider($this->serviceProvider);
        $result    = new Result();

        $validator->validate($assertion, $result);

        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
    }


    /**
     * @group assertion-validation
     * @test
     * @return void
     */
    public function the_assertion_is_valid_when_the_current_sp_entity_id_is_a_valid_audience(): void
    {
        // Create an assertion
        $assertion = new Assertion($this->issuer, null, null, null, $this->conditions, [$this->authnStatement]);

        $this->serviceProvider->shouldReceive('getEntityId')->andReturn('audience1');

        $validator = new SpIsValidAudience();
        $validator->setServiceProvider($this->serviceProvider);
        $result    = new Result();

        $validator->validate($assertion, $result);

        $this->assertTrue($result->isValid());
    }
}
