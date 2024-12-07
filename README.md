# IDSRuleParser

**IDSRuleParser** is a lightweight, framework-agnostic PHP library for parsing Intrusion Detection System (IDS) rules, such as Suricata or Snort rules. It provides tools to extract and manipulate key components of IDS rules, making it easier to process, validate, and analyze them programmatically.

This is a port from py-suricataparser on https://github.com/m-chrome/py-suricataparser


## Features

- Parse individual IDS rules and extract their components.
- Support for rule options, including metadata parsing.
- Framework-independent for broad compatibility.
- Easy-to-extend structure for handling additional rule attributes.

---

## Installation

To include `IDSRuleParser` in your project, use Composer to add it as a dependency:

```bash
composer require titoshadow/ids-rule-parser
```

## Contributing