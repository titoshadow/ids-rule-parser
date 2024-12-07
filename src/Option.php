<?php

namespace IDSRuleParser;

class Option
{
    const string CLASSTYPE = 'classtype';
    const string GID = 'gid';
    const string METADATA = 'metadata';
    const string MSG = 'msg';
    const string REV = 'rev';
    const string SID = 'sid';

    public string $name {
        get {
            return $this->name;
        }
    }
    public mixed $value {
        get {
            return $this->value;
        }
    }

    public function __construct($name, $value = null)
    {
        $this->name = $name;
        $this->value = $value;
    }


    public function __toString()
    {
        if (!$this->value) {
            return "{$this->name};";
        }
        return "{$this->name}:{$this->value};";
    }


}
