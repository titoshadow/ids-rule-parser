<?php

declare(strict_types=1);

namespace IDSRuleParser;

class Rule
{
    public bool $enabled;

    public string $action;

    public string $header;

    /** @var list<Option> */
    public array $options;

    public ?string $raw;

    private string $msg;

    private int $sid;

    private int $gid;

    private int $rev;

    private int $priority;

    private string $classtype;

    private string $target;

    /**
     * @param  list<Option>  $options
     */
    public function __construct(bool $enabled, string $action, string $header, array $options, ?string $raw = null)
    {
        $this->enabled = $enabled;
        $this->action = $action;
        $this->header = $header;
        $this->options = $options;
        $this->raw = $raw;

        if ($raw !== null && $raw !== '') {
            $this->buildOptions();
        } else {
            $this->buildRule();
        }
    }

    public function __toString(): string
    {
        return ($this->enabled ? '' : '# ').$this->raw;
    }

    private function buildOptions(): void
    {
        $metadata = [];
        $propertyMap = [
            Option::MSG => function (mixed $value): void {
                $this->msg = trim((string) $value, '"');
            },
            Option::SID => function (mixed $value): void {
                $this->sid = (int) $value;
            },
            Option::GID => function (mixed $value): void {
                $this->gid = (int) $value;
            },
            Option::REV => function (mixed $value): void {
                $this->rev = (int) $value;
            },
            Option::PRIORITY => function (mixed $value): void {
                $this->priority = (int) $value;
            },
            Option::CLASSTYPE => function (mixed $value): void {
                $this->classtype = (string) $value;
            },
            Option::TARGET => function (mixed $value): void {
                $this->target = (string) $value;
            },
            Option::METADATA => function (mixed $value) use (&$metadata): void {
                if ($value instanceof Metadata) {
                    $metadata = array_merge($metadata, $value->data);
                }
            },
        ];

        foreach ($this->options as $option) {
            if (array_key_exists($option->name, $propertyMap)) {
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
        $value = $this->firstOptionValue(Option::SID);

        return $value !== null ? (int) $value : null;
    }

    public function getRev(): ?int
    {
        $value = $this->firstOptionValue(Option::REV);

        return $value !== null ? (int) $value : null;
    }

    public function getMsg(): ?string
    {
        $value = $this->firstOptionValue(Option::MSG);

        return $value !== null ? (string) $value : null;
    }

    public function getPriority(): ?int
    {
        $value = $this->firstOptionValue(Option::PRIORITY);

        return $value !== null ? (int) $value : null;
    }

    public function getTarget(): ?string
    {
        foreach ($this->options as $option) {
            if ($option->name === Option::TARGET && in_array($option->value, ['src_ip', 'dest_ip'], true)) {
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

    /**
     * @return list<Option>
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    private function buildRule(): void
    {
        $options = implode(' ', array_map(static fn (Option $option): string => (string) $option, $this->options));
        $this->raw = "{$this->action} {$this->header} ({$options})";
        $this->buildOptions();
    }

    public function addOption(string $name, mixed $value = null, ?int $index = null): void
    {
        $option = new Option($name, $value);

        if ($index === null) {
            $this->options[] = $option;
        } else {
            array_splice($this->options, $index, 0, [$option]);
        }

        $this->buildRule();
    }

    /**
     * @return array{enabled: bool, action: string, header: string, options: list<array{name: string, value: mixed}>}
     */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'action' => $this->action,
            'header' => $this->header,
            'options' => array_map(static fn (Option $option): array => [
                'name' => $option->name,
                'value' => $option->value instanceof Metadata ? $option->value->data : $option->value,
            ], $this->options),
        ];
    }

    private function firstOptionValue(string $name): mixed
    {
        foreach ($this->options as $option) {
            if ($option->name === $name) {
                return $option->value;
            }
        }

        return null;
    }
}
