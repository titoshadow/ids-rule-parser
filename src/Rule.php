<?php

namespace IDSRuleParser;


class Rule
{
    public bool $enabled;
    public string $action {
        get {
            return $this->action;
        }
    }
    public string $header {
        get {
            return $this->header;
        }
    }
    public array $options {
        &get {
            return $this->options;
        }
    }
    public ?string $raw {
        get {
            return $this->raw;
        }
    }

    private string $msg;
    private int $sid;
    private int $gid;
    private int $rev;
    private string $classtype;


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

        foreach ($this->options as $option) {
            if ($option->name === Option::MSG) {
                $this->msg = trim($option->value, '"');
            } elseif ($option->name === Option::SID) {
                $this->sid = (int)$option->value;
            } elseif ($option->name === Option::GID) {
                $this->gid = (int)$option->value;
            } elseif ($option->name === Option::REV) {
                $this->rev = (int)$option->value;
            } elseif ($option->name === Option::CLASSTYPE) {
                $this->classtype = $option->value;
            } elseif ($option->name === Option::METADATA) {
                $metadata = array_merge($metadata, $option->value->data);
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
            ], $this->options), // Replacing `map` with `array_map`
        ];
    }
}
