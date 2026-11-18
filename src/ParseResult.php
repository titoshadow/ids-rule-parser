<?php

declare(strict_types=1);

namespace IDSRuleParser;

use IDSRuleParser\Exceptions\RuleParserException;

/**
 * The rules parsed from a list or a file, and why the malformed ones were rejected.
 */
final readonly class ParseResult
{
    /**
     * @param  list<Rule>  $rules
     * @param  array<array-key, RuleParserException>  $errors  Keyed like the input lines (file: line number from 1).
     */
    public function __construct(
        private array $rules,
        private array $errors,
    ) {}

    /**
     * @return list<Rule>
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * @return array<array-key, RuleParserException>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    public function hasErrors(): bool
    {
        return $this->errors !== [];
    }
}
