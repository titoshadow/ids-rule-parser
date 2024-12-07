<?php

use PHPUnit\Framework\TestCase;
use IDSRuleParser\RuleParser;
use IDSRuleParser\Exceptions\RuleParserException;

class ParserTest extends TestCase
{
    /**
     * @throws RuleParserException
     */
    public function testParseRule()
    {
        $parser = new RuleParser();
        $rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
            . '(msg: ET CURRENT_EVENTS Request to .in FakeAV Campaign June '
            . '19 2012 exe or zip; flow:established,to_server; content:"setup."; '
            . 'fast_pattern:only; http_uri; content:".in|0d 0a|"; flowbits:isset,somebit; '
            . 'flowbits:unset,otherbit; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?'
            . 'setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; '
            . 'reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; '
            . 'classtype:trojan-activity; sid:2014929; rev:1;)';

        $parsedRule = $parser->parseRule($rule);

        $this->assertTrue($parsedRule->enabled);
        $this->assertEquals("alert", $parsedRule->action);
        $this->assertEquals('tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS', $parsedRule->header);
        $this->assertEquals(2014929, $parsedRule->getSid());
        $this->assertEquals(1, $parsedRule->getRev());
        $this->assertEquals("ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip", $parsedRule->getMsg());
        $this->assertCount(16, $parsedRule->options);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseDisabledRule()
    {
        $parser = new RuleParser();
        $rule = '# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertFalse($parsedRule->enabled);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseDoubleCommentedRule()
    {
        $parser = new RuleParser();
        $rule = '## alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertFalse($parsedRule->enabled);
        $this->assertEquals('alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)', $parsedRule->raw);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseRuleWithList()
    {
        $parser = new RuleParser();
        $rule = 'alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; http_uri;)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertNotNull($parsedRule);
        $this->assertTrue($parsedRule->enabled);
        $this->assertEquals("alert", $parsedRule->action);
        $this->assertEquals("http any any -> [1.1.1.1, 1.1.1.2] any", $parsedRule->header);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseRuleWithBrokenOptions()
    {
        $parser = new RuleParser();
        $this->expectException(RuleParserException::class);

        $rule = 'alert tcp any any -> any any (sid:1)';
        $parser->parseRule($rule);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseRuleWithWrongAction()
    {
        $parser = new RuleParser();
        $rule = 'dig tcp any any - any any (sid:1;)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertNull($parsedRule);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseFile()
    {
        $parser = new RuleParser();
        $rule = 'alert tcp any any -> any any (sid:1;)';

        $filePath = tempnam(sys_get_temp_dir(), 'rules');
        file_put_contents($filePath, $rule);

        $parsedRules = $parser->parseFile($filePath);

        $this->assertCount(1, $parsedRules);
        $parsedRule = $parsedRules[0];
        $this->assertTrue($parsedRule->isEnabled());
        $this->assertEquals("alert", $parsedRule->action);
        $this->assertEquals(1, $parsedRule->getSid());

        unlink($filePath);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseRules()
    {
        $parser = new RuleParser();
        $rules = [
            'alert tcp any any -> any any (sid:1;)',
        ];

        $parsedRules = $parser->parseRules($rules);

        $this->assertCount(1, $parsedRules);
        $parsedRule = $parsedRules[0];
        $this->assertTrue($parsedRule->isEnabled());
        $this->assertEquals("alert", $parsedRule->action);
        $this->assertEquals(1, $parsedRule->getSid());
    }

    /**
     * @throws RuleParserException
     */
    public function testParseRuleWithEmptyMetadata()
    {
        $parser = new RuleParser();
        $this->expectException(RuleParserException::class);

        $rule = 'alert tcp any any -> any any (sid:1; metadata;)';
        $parser->parseRule($rule);
    }
}
