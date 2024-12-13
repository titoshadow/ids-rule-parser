<?php

namespace IDSRuleParser;


class Rule
{
    public bool $enabled;
    public string $action;

    public string $header;
    public array $options;
    public ?string $raw;

    private string $msg;
    private int $sid;
    private int $gid;
    private int $rev;

    private int $priority;
    private string $classtype;
    private string $target;


    public function __construct(bool $enabled, string $action, string $header, array $options, ?string $raw = null)
    {
        $this->enabled = $enabled;
        $this->action = $action;
        $this->header = $header;
        $this->options = $options;
        $this->raw = $raw;

        if ($raw) {
            $this->buildOptions();
        } else {
            $this->buildRule();
        }
    }

    public function __toString(): string
    {
        return ($this->enabled ? '' : '# ') . $this->raw;
    }

    private function buildOptions(): void
    {
        $metadata = [];
        $propertyMap = [
            Option::MSG => function ($value) { $this->msg = trim($value, '"'); },
            Option::SID => function ($value) { $this->sid = (int)$value; },
            Option::GID => function ($value) { $this->gid = (int)$value; },
            Option::REV => function ($value) { $this->rev = (int)$value; },
            Option::PRIORITY => function ($value) { $this->priority = (int)$value; },
            Option::CLASSTYPE => function ($value) { $this->classtype = $value; },
            Option::TARGET => function ($value) { $this->target = $value; },
            Option::METADATA => function ($value) use (&$metadata) { $metadata = array_merge($metadata, $value->data); },
        ];

        foreach ($this->options as $option) {
            if (isset($propertyMap[$option->name])) {
                $propertyMap[$option->name]($option->value);
            }
        }
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getSid(): ?int
    {
        foreach ($this->options as $option) {
            if ($option instanceof Option && $option->name === 'sid') {
                return (int)$option->value;
            }
        }
        return null;
    }


    public function getRev(): ?int
    {
        foreach ($this->options as $option) {
            if ($option instanceof Option && $option->name === 'rev') {
                return (int)$option->value;
            }
        }
        return null;
    }

    public function getMsg(): ?string
    {
        foreach ($this->options as $option) {
            if ($option instanceof Option && $option->name === 'msg') {
                return $option->value;
            }
        }
        return null;
    }

    public function getPriority(): ?int
    {
        foreach ($this->options as $option) {
            if ($option instanceof Option && $option->name === 'priority') {
                return (int)$option->value;
            }
        }
        return null;
    }

    public function getTarget(): ?string
    {
        foreach ($this->options as $option) {
            if ($option instanceof Option && $option->name === 'target') {
                if ($option->value === 'src_ip' || $option->value === 'dest_ip')
                    return $option->value;
            }
        }
        return null;
    }

    public function getRaw(): ?string
    {
        return $this->raw;
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function getHeader(): string
    {
        return $this->header;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    private function buildRule(): void
    {
        $options = implode(' ', array_map(fn($opt) => (string)$opt, $this->options));
        $this->raw = "{$this->action} {$this->header} ({$options})";
        $this->buildOptions();
    }

    public function addOption(string $name, $value = null, ?int $index = null): void
    {
        $option = new Option($name, $value);

        if ($index === null) {
            $this->options[] = $option;
        } else {
            array_splice($this->options, $index, 0, [$option]);
        }

        $this->buildRule();
    }

    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'action' => $this->action,
            'header' => $this->header,
            'options' => array_map(fn($opt) => [
                'name' => $opt->name,
                'value' => $opt->value instanceof Metadata ? $opt->value->data : $opt->value,
            ], $this->options),
        ];
    }
}
