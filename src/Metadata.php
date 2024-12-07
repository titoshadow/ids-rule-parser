<?php

namespace IDSRuleParser;

class Metadata
{
    public array $data;

    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function __toString(): string
    {
        return implode(', ', $this->data);
    }

    public function addMeta(string $name, string $value): array
    {
        $this->data[] = "{$name} {$value}";
        return $this->data;
    }

    public function popMeta(string $name): array
    {
        $removed = [];
        $this->data = array_filter($this->data, function ($meta) use ($name, &$removed) {
            if (str_starts_with($meta, $name)) {
                $removed[] = $meta;
                return false;
            }
            return true;
        });
        return $removed;
    }
}
