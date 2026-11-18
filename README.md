# IDSRuleParser

Lightweight, native PHP library for parsing IDS rules, such as Suricata or Snort rules. 

This is a port from py-suricataparser on https://github.com/m-chrome/py-suricataparser


## Features

- Parse individual IDS rules, lists or files.
- Options are split the way Suricata splits them: an option ends at the first `;` not escaped with `\`, so the
  parsed `sid` is the one Suricata applies.
- Rules Suricata would reject are rejected too: duplicated `sid`, `rev`, `gid`, `msg`, `classtype` or `priority`,
  or a quoted value that is never closed.
- One malformed rule in a list or file does not stop the others.
- Framework-independent 

---

## Installation

To include `IDSRuleParser` in your project, use Composer to add it as a dependency:

```bash
composer require titoshadow/ids-rule-parser
```

## Usage

```php
use IDSRuleParser\Exceptions\RuleParserException;
use IDSRuleParser\RuleParser;

$parser = new RuleParser();

// One rule: null when the line is not a rule, an exception when it is a malformed one.
$rule = $parser->parseRule('alert tcp any any -> any any (msg:"Example"; sid:1; rev:1;)');
$rule->getSid(); // 1

// A list or a file: the valid rules, and why the others were rejected.
$result = $parser->parseFile('/etc/suricata/rules/local.rules');

foreach ($result->getRules() as $rule) {
    // ...
}

foreach ($result->getErrors() as $line => $error) {
    // $line: the input key (for a file, the line number from 1)
    echo $line, ': ', $error->getReason(), PHP_EOL;
}
```

## Upgrading from 1.x

- `parseRules()` and `parseFile()` return a `ParseResult` (`getRules()`, `getErrors()`, `hasErrors()`) instead of an
  array, and no longer throw on a malformed rule.
- Options are tokenized like Suricata does. A quoted value that is not closed (`msg:"a; sid:2;"`) and repeated
  `sid`, `rev`, `gid`, `msg`, `classtype` or `priority` options now throw a `RuleParserException`.
- The actions `rejectsrc`, `rejectdst`, `rejectboth` and `accept` are recognised.
- A PCRE failure throws a `RuleParserException` instead of being taken for a line that is not a rule.
