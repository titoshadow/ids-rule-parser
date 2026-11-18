<?php

declare(strict_types=1);

namespace IDSRuleParser\Exceptions;

use Exception;
use Throwable;

class RuleParserException extends Exception
{
    protected string $rule;

    protected string $reason;

    /**
     * @param  string  $message  Why the rule was rejected.
     * @param  string  $rule  The rule that caused the exception.
     * @param  int  $code  The exception code (default: 0).
     * @param  Throwable|null  $previous  Previous exception (default: null).
     */
    public function __construct(string $message, string $rule, int $code = 0, ?Throwable $previous = null)
    {
        $this->rule = $rule;
        $this->reason = $message;
        parent::__construct("{$message}. Problematic Rule: {$rule}", $code, $previous);
    }

    public function getRule(): string
    {
        return $this->rule;
    }

    /**
     * Why the rule was rejected, without the rule.
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
