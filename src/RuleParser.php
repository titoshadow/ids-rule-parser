<?php

declare(strict_types=1);

namespace IDSRuleParser;

use IDSRuleParser\Exceptions\RuleParserException;

class RuleParser
{
    private const string RULE_PATTERN = '/^(#+)?\s*(?<raw>(?<header>[^()]+)\((?<options>.*)\))$/s';

    /**
     * Rule actions of Suricata (up to 8) and Snort.
     */
    public const array ACTIONS = [
        'alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth', 'accept', 'log', 'sdrop',
    ];

    /**
     * Options that Suricata accepts only once per rule.
     */
    public const array UNIQUE_OPTIONS = [
        Option::SID, Option::REV, Option::GID, Option::MSG, Option::CLASSTYPE, Option::PRIORITY,
    ];

    /**
     * @throws RuleParserException
     */
    public function parseMetadata(string $buffer): Metadata
    {
        if (trim($buffer) === '') {
            throw new RuleParserException('Metadata cannot be empty', $buffer);
        }

        $items = array_map(trim(...), explode(',', $buffer));

        return new Metadata($items);
    }

    /**
     * Splits the options the way Suricata does: an option ends at the first `;` not preceded by `\`, whatever the
     * quotes around it, and its name ends at the first `:`. A value whose unescaped double quotes do not pair up is
     * rejected, as Suricata rejects the rule: `msg:"a; sid:2;"` must not read as `sid:2`.
     *
     * @return list<Option>
     *
     * @throws RuleParserException
     */
    public function parseOptions(string $buffer): array
    {
        $buffer = trim($buffer);
        if (! str_ends_with($buffer, ';') || str_ends_with($buffer, '\\;')) {
            throw new RuleParserException("Options must end with ';'", $buffer);
        }

        $options = [];
        $seen = [];
        $start = 0;
        $length = strlen($buffer);

        for ($i = 0; $i < $length; $i++) {
            if ($buffer[$i] !== ';' || ($i > 0 && $buffer[$i - 1] === '\\')) {
                continue;
            }

            $part = trim(substr($buffer, $start, $i - $start));
            $start = $i + 1;

            if ($part === '') {
                continue;
            }

            $option = $this->parseOption($part, $buffer);

            if (in_array($option->name, self::UNIQUE_OPTIONS, true)) {
                if (array_key_exists($option->name, $seen)) {
                    throw new RuleParserException("Duplicated '{$option->name}' option", $buffer);
                }

                $seen[$option->name] = true;
            }

            $options[] = $option;
        }

        return $options;
    }

    /**
     * Parses one rule line. Returns null for a line that is not a rule (no options block, unknown action).
     *
     * @throws RuleParserException When the line is a rule but malformed, or the pattern cannot be evaluated.
     */
    public function parseRule(string $buffer): ?Rule
    {
        $buffer = trim($buffer);
        $matched = preg_match(self::RULE_PATTERN, $buffer, $matches);

        if ($matched === false) {
            throw new RuleParserException('Rule pattern failed: '.preg_last_error_msg(), $buffer);
        }

        if ($matched === 0) {
            return null;
        }

        // A rule is enabled (not commented out) if it does not start with any `#`
        $enabled = $matches[1] === '';

        $headerParts = preg_split('/\s+/', trim($matches['header']), 2);
        if ($headerParts === false) {
            throw new RuleParserException('Header split failed: '.preg_last_error_msg(), $buffer);
        }

        if (count($headerParts) !== 2) {
            return null;
        }

        [$action, $header] = $headerParts;

        if (! in_array($action, self::ACTIONS, true)) {
            return null;
        }

        try {
            $options = $this->parseOptions($matches['options']);
        } catch (RuleParserException $exception) {
            throw new RuleParserException($exception->getReason(), $buffer, previous: $exception);
        }

        return new Rule($enabled, $action, $header, $options, $matches['raw']);
    }

    /**
     * Parses each line on its own: a malformed rule is reported in the result, never stops the others. Lines that are
     * not rules are skipped.
     *
     * @param  array<array-key, string>  $rules
     */
    public function parseRules(array $rules): ParseResult
    {
        $parsed = [];
        $errors = [];

        foreach ($rules as $key => $rule) {
            try {
                $parsedRule = $this->parseRule($rule);
            } catch (RuleParserException $exception) {
                $errors[$key] = $exception;

                continue;
            }

            if ($parsedRule !== null) {
                $parsed[] = $parsedRule;
            }
        }

        return new ParseResult($parsed, $errors);
    }

    /**
     * Parses the enabled rules of a file; errors are keyed by line number (from 1).
     *
     * @throws RuleParserException When the file cannot be read.
     */
    public function parseFile(string $filePath): ParseResult
    {
        if (! is_file($filePath) || ! is_readable($filePath)) {
            throw new RuleParserException('Rules file cannot be found or is not readable', $filePath);
        }

        $lines = file($filePath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new RuleParserException('Rules file cannot be read', $filePath);
        }

        $rules = [];
        foreach ($lines as $index => $line) {
            $line = trim($line);
            // Skip disabled rules, comments and empty lines
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $rules[$index + 1] = $line;
        }

        return $this->parseRules($rules);
    }

    /**
     * @throws RuleParserException
     */
    private function parseOption(string $part, string $buffer): Option
    {
        [$name, $value] = array_pad(explode(':', $part, 2), 2, null);
        $name = trim((string) $name);
        $value = $value !== null ? trim($value) : '';

        if (preg_match('/^[A-Za-z0-9_.\-]+$/', $name) !== 1) {
            throw new RuleParserException("Invalid option name '{$name}'", $buffer);
        }

        if (! $this->isProperlyQuoted($value)) {
            throw new RuleParserException("Unterminated quoted value in option '{$name}'", $buffer);
        }

        if ($name === Option::METADATA) {
            return new Option($name, $this->parseMetadata($value));
        }

        return new Option($name, $value);
    }

    /**
     * A value that opens with a double quote, optionally negated (`"…"`, `!"…"`), must end with an unescaped one
     * (`"a\\"` is closed, `"a\"` is not), as Suricata requires for msg, content or pcre. Inner quotes are allowed:
     * pcre takes everything between the first and the last quote. Other values (`reference:url,"…"`) are left alone.
     */
    private function isProperlyQuoted(string $value): bool
    {
        if (str_starts_with($value, '!')) {
            $value = ltrim(substr($value, 1));
        }

        if (! str_starts_with($value, '"')) {
            return true;
        }

        $length = strlen($value);
        if ($length < 2 || $value[$length - 1] !== '"') {
            return false;
        }

        $backslashes = strlen($value) - 1 - strlen(rtrim(substr($value, 0, -1), '\\'));

        return $backslashes % 2 === 0;
    }
}
