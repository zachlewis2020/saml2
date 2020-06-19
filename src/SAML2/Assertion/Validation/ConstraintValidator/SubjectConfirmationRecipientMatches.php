<?php

declare(strict_types=1);

namespace SAML2\Assertion\Validation\ConstraintValidator;

use SAML2\Assertion\Validation\Result;
use SAML2\Assertion\Validation\SubjectConfirmationConstraintValidator;
use SAML2\Configuration\Destination;
use SAML2\XML\saml\SubjectConfirmation;
use SimpleSAML\Assert\Assert;

class SubjectConfirmationRecipientMatches implements
    SubjectConfirmationConstraintValidator
{
    /**
     * @var \SAML2\Configuration\Destination
     */
    private $destination;


    /**
     * Constructor for SubjectConfirmationRecipientMatches
     * @param \SAML2\Configuration\Destination $destination
     */
    public function __construct(Destination $destination)
    {
        $this->destination = $destination;
    }


    /**
     * @param \SAML2\XML\saml\SubjectConfirmation $subjectConfirmation
     * @param \SAML2\Assertion\Validation\Result $result
     * @return void
     *
     * @throws \SimpleSAML\Assert\AssertionFailedException if assertions are false
     */
    public function validate(SubjectConfirmation $subjectConfirmation, Result $result): void
    {
        $data = $subjectConfirmation->getSubjectConfirmationData();
        Assert::notNull($data);

        /** @psalm-suppress PossiblyNullReference */
        $recipient = $data->getRecipient();
        if ($recipient && !$this->destination->equals(new Destination($recipient))) {
            $result->addError(sprintf(
                'Recipient in SubjectConfirmationData ("%s") does not match the current destination ("%s")',
                $recipient,
                strval($this->destination)
            ));
        }
    }
}
