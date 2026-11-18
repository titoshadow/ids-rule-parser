<?php

declare(strict_types=1);

namespace IDSRuleParser;

use Stringable;

class Metadata implements Stringable
{
    /** @var list<string> */
    public array $data;

    /**
     * @param  list<string>  $data
     */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function __toString(): string
    {
        return implode(', ', $this->data);
    }

    /**
     * @return list<string>
     */
    public function addMeta(string $name, string $value): array
    {
        $this->data[] = "{$name} {$value}";

        return $this->data;
    }

    /**
     * @return list<string>
     */
    public function popMeta(string $name): array
    {
        $removed = [];
        $this->data = array_values(array_filter($this->data, static function (string $meta) use ($name, &$removed): bool {
            if (str_starts_with($meta, $name)) {
                $removed[] = $meta;

                return false;
            }

            return true;
        }));

        return $removed;
    }
}
