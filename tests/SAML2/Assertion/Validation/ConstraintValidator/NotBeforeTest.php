<?php

declare(strict_types=1);

namespace SAML2\Assertion\Validation\ConstraintValidator;

use Mockery;
use SAML2\Assertion\Validation\ConstraintValidator\NotBefore;
use SAML2\Assertion\Validation\Result;
use SAML2\ControlledTimeTest;
use SAML2\XML\saml\Assertion;
use SAML2\XML\saml\AuthnContext;
use SAML2\XML\saml\AuthnContextClassRef;
use SAML2\XML\saml\AuthnStatement;
use SAML2\XML\saml\Conditions;
use SAML2\XML\saml\Issuer;

/**
 * Because we're mocking a static call, we have to run it in separate processes so as to no contaminate the other
 * tests.
 *
 * @runTestsInSeparateProcesses
 */
class NotBeforeTest extends ControlledTimeTest
{
    /**
     * @var \SAML2\XML\saml\Issuer
     */
    private $issuer;

    /**
     * @var \SAML2\XML\saml\AuthnStatement
     */
    private $authnStatement;


    /**
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // Create an Issuer
        $this->issuer = new Issuer('testIssuer');

        // Create the statements
        $this->authnStatement = new AuthnStatement(
            new AuthnContext(
                new AuthnContextClassRef('someAuthnContext'),
                null,
                null
            ),
            time()
        );
    }


    /**
     * @group assertion-validation
     * @test
     * @return void
     */
    public function timestamp_in_the_future_beyond_graceperiod_is_not_valid(): void
    {
        // Create Conditions
        $conditions = new Conditions($this->currentTime + 61);

        // Create an assertion
        $assertion = new Assertion($this->issuer, null, null, null, $conditions, [$this->authnStatement]);

        $validator = new NotBefore();
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
    public function time_within_graceperiod_is_valid(): void
    {
        // Create Conditions
        $conditions = new Conditions($this->currentTime + 60);

        // Create an assertion
        $assertion = new Assertion($this->issuer, null, null, null, $conditions, [$this->authnStatement]);

        $validator = new NotBefore();
        $result    = new Result();

        $validator->validate($assertion, $result);

        $this->assertTrue($result->isValid());
    }


    /**
     * @group assertion-validation
     * @test
     * @return void
     */
    public function current_time_is_valid(): void
    {
        // Create Conditions
        $conditions = new Conditions($this->currentTime);

        // Create an assertion
        $assertion = new Assertion($this->issuer, null, null, null, $conditions, [$this->authnStatement]);

        $validator = new NotBefore();
        $result    = new Result();

        $validator->validate($assertion, $result);

        $this->assertTrue($result->isValid());
    }
}
