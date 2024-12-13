<?php

namespace IDSRuleParser\Exceptions;

use Exception;
use Throwable;

class RuleParserException extends Exception
{
    protected string $rule;


    /**
     * RuleParserException constructor.
     *
     * @param string $message The exception message.
     * @param string $rule The rule that caused the exception.
     * @param int $code The exception code (default: 0).
     * @param Throwable|null $previous Previous exception (default: null).
     */
    public function __construct(string $message, string $rule, int $code = 0, ?Throwable $previous = null)
    {
        $this->rule = $rule;
        $message = "{$message}. Problematic Rule: {$rule}";
        parent::__construct($message, $code, $previous);
    }

    public function getRule(): string
    {
        return $this->rule;
    }
}
