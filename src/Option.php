<?php

declare(strict_types=1);

namespace IDSRuleParser;

use Stringable;

class Option implements Stringable
{
    public const string CLASSTYPE = 'classtype';

    public const string GID = 'gid';

    public const string METADATA = 'metadata';

    public const string MSG = 'msg';

    public const string REV = 'rev';

    public const string SID = 'sid';

    public const string TARGET = 'target';

    public const string PRIORITY = 'priority';

    public string $name;

    public mixed $value;

    public function __construct(string $name, mixed $value = null)
    {
        $this->name = $name;
        $this->value = $value;
    }

    public function __toString(): string
    {
        if ($this->value === null || $this->value === '') {
            return "{$this->name};";
        }

        return "{$this->name}:{$this->value};";
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getValue(): mixed
    {
        return $this->value;
    }
}
