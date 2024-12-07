<?php

namespace IDSRuleParser;

use IDSRuleParser\Exceptions\RuleParserException;

class RuleParser
{
    private const string RULE_PATTERN = '/^(#+)?\s*(?<raw>(?<header>[^()]+)\((?<options>.*)\))$/';


    /**
     * @throws RuleParserException
     */
    public function parseMetadata(string $buffer): Metadata
    {
        if (trim($buffer) === '') {
            throw new RuleParserException("Metadata cannot be empty.", $buffer);
        }

        $items = array_map('trim', explode(',', $buffer));
        return new Metadata($items);
    }


    /**
     * @throws RuleParserException
     */
    public function parseOptions(string $buffer): array
    {
        $buffer = trim($buffer);
        if (!str_ends_with($buffer, ';')) {
            throw new RuleParserException("Options must end with ';'", $buffer);
        }

        $parts = explode(';', rtrim($buffer, ';'));
        $options = [];

        foreach ($parts as $part) {
            [$name, $value] = array_pad(explode(':', $part, 2), 2, null);
            $name = trim($name);
            $value = $value !== null ? trim($value) : '';

            if ($name === Option::METADATA) {
                $value = $this->parseMetadata($value);
            }

            $options[] = new Option($name, $value);
        }

        return $options;
    }


    /**
     * @throws RuleParserException
     */
    public function parseRule(string $buffer): ?Rule
    {
        $buffer = trim($buffer);
        if (!preg_match(self::RULE_PATTERN, $buffer, $matches)) {
            return null; // Rule pattern does not match
        }

        // A rule is enabled (not commented out) if it does not start with any `#`
        $enabled = !isset($matches[1]) || $matches[1] === '';

        $headerParts = preg_split('/\s+/', trim($matches['header']), 2);
        if (count($headerParts) !== 2) {
            return null; // Header format is invalid
        }

        [$action, $header] = $headerParts;

        $validActions = ['alert', 'log', 'pass', 'drop', 'reject', 'sdrop'];
        if (!in_array($action, $validActions, true)) {
            return null; // Invalid action
        }

        $options = $this->parseOptions($matches['options']);

        return new Rule($enabled, $action, $header, $options, $matches['raw']);
    }


    /**
     * @throws RuleParserException
     */
    public function parseRules(array $rules): array
    {
        $output = [];

        foreach ($rules as $rule){
            $output[] = $this->parseRule($rule);
        }

        return $output;
    }


    /**
     * @throws RuleParserException
     */
    public function parseFile(string $filePath): array
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            throw new RuleParserException("Rules file cannot be found or is not readable.", $filePath);
        }

        $rules = [];
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        foreach ($lines as $line) {
            $line = trim($line);
            // Skip comments or empty lines
            if (empty($line) || str_starts_with($line, '#')) {
                continue;
            }

            $rule = $this->parseRule($line);
            if ($rule !== null) {
                $rules[] = $rule;
            }
        }

        return $rules;
    }
}
