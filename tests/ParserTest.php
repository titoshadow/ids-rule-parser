<?php

declare(strict_types=1);

use IDSRuleParser\Exceptions\RuleParserException;
use IDSRuleParser\Metadata;
use IDSRuleParser\RuleParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ParserTest extends TestCase
{
    /**
     * @throws RuleParserException
     */
    public function testParseRule(): void
    {
        $parser = new RuleParser();
        $rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
            .'(msg: ET CURRENT_EVENTS Request to .in FakeAV Campaign June '
            .'19 2012 exe or zip; flow:established,to_server; content:"setup."; '
            .'fast_pattern:only; http_uri; content:".in|0d 0a|"; flowbits:isset,somebit; '
            .'flowbits:unset,otherbit; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?'
            .'setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; '
            .'reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; '
            .'classtype:trojan-activity; sid:2014929; rev:1; priority:7; target:src_ip;)';

        $parsedRule = $parser->parseRule($rule);

        $this->assertTrue($parsedRule->enabled);
        $this->assertEquals('alert', $parsedRule->action);
        $this->assertEquals('tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS', $parsedRule->header);
        $this->assertEquals(2014929, $parsedRule->getSid());
        $this->assertEquals(1, $parsedRule->getRev());
        $this->assertEquals(7, $parsedRule->getPriority());
        $this->assertEquals('src_ip', $parsedRule->getTarget());
        $this->assertEquals('ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip', $parsedRule->getMsg());
        $this->assertCount(18, $parsedRule->options);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseDisabledRule(): void
    {
        $parser = new RuleParser();
        $rule = '# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertFalse($parsedRule->enabled);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseDoubleCommentedRule(): void
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
    public function testParseRuleWithList(): void
    {
        $parser = new RuleParser();
        $rule = 'alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; http_uri;)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertNotNull($parsedRule);
        $this->assertTrue($parsedRule->enabled);
        $this->assertEquals('alert', $parsedRule->action);
        $this->assertEquals('http any any -> [1.1.1.1, 1.1.1.2] any', $parsedRule->header);
    }

    public function testParseRuleWithBrokenOptions(): void
    {
        $parser = new RuleParser();
        $this->expectException(RuleParserException::class);

        $rule = 'alert tcp any any -> any any (sid:1)';
        $parser->parseRule($rule);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseRuleWithWrongAction(): void
    {
        $parser = new RuleParser();
        $rule = 'dig tcp any any - any any (sid:1;)';
        $parsedRule = $parser->parseRule($rule);

        $this->assertNull($parsedRule);
    }

    /**
     * @throws RuleParserException
     */
    public function testParseFile(): void
    {
        $parser = new RuleParser();
        $rule = 'alert tcp any any -> any any (sid:1;)';

        $filePath = tempnam(sys_get_temp_dir(), 'rules');
        file_put_contents($filePath, $rule);

        try {
            $result = $parser->parseFile($filePath);
        } finally {
            unlink($filePath);
        }

        $this->assertFalse($result->hasErrors());
        $this->assertCount(1, $result->getRules());
        $parsedRule = $result->getRules()[0];
        $this->assertTrue($parsedRule->isEnabled());
        $this->assertEquals('alert', $parsedRule->action);
        $this->assertEquals(1, $parsedRule->getSid());
    }

    public function testParseRules(): void
    {
        $parser = new RuleParser();
        $rules = [
            'alert tcp any any -> any any (sid:1;)',
        ];

        $result = $parser->parseRules($rules);

        $this->assertCount(1, $result->getRules());
        $parsedRule = $result->getRules()[0];
        $this->assertTrue($parsedRule->isEnabled());
        $this->assertEquals('alert', $parsedRule->action);
        $this->assertEquals(1, $parsedRule->getSid());
    }

    public function testParseRuleWithEmptyMetadata(): void
    {
        $parser = new RuleParser();
        $this->expectException(RuleParserException::class);

        $rule = 'alert tcp any any -> any any (sid:1; metadata;)';
        $parser->parseRule($rule);
    }

    /**
     * A `;` inside a quoted msg ends the option, as in Suricata: the msg is left unterminated and the rule rejected,
     * instead of reading the text after it as a second sid.
     */
    public function testAnUnescapedSemicolonInAQuotedValueDoesNotInjectAnOption(): void
    {
        $parser = new RuleParser();

        $this->expectException(RuleParserException::class);
        $this->expectExceptionMessage("Unterminated quoted value in option 'msg'");

        $parser->parseRule('alert tcp any any -> any any (msg:"hello; sid:999; x"; sid:1; rev:1;)');
    }

    /**
     * @throws RuleParserException
     */
    public function testEscapedSemicolonsAndQuotesStayInTheValue(): void
    {
        $parser = new RuleParser();
        $rule = $parser->parseRule('alert tcp any any -> any any (msg:"a\;b \"quoted\" sid:999\;"; content:"x|3b|y"; sid:1; rev:2;)');

        $this->assertNotNull($rule);
        $this->assertSame(1, $rule->getSid());
        $this->assertSame(2, $rule->getRev());
        $this->assertSame('"a\;b \"quoted\" sid:999\;"', $rule->getMsg());
        $this->assertSame('"x|3b|y"', $rule->options[1]->value);
        $this->assertCount(4, $rule->options);
    }

    /**
     * Suricata's pcre takes everything between the first and the last quote (seen in ET Open).
     *
     * @throws RuleParserException
     */
    public function testInnerQuotesOfAnEnclosedValueAreAllowed(): void
    {
        $rule = (new RuleParser())->parseRule('alert http any any -> any any (pcre:"/^["\']?post/Ri"; content:!"x"; sid:8;)');

        $this->assertSame('"/^["\']?post/Ri"', $rule->options[0]->value);
        $this->assertSame('!"x"', $rule->options[1]->value);
        $this->assertSame(8, $rule->getSid());
    }

    /**
     * Quotes that do not open the value are not checked (seen in ET Open).
     *
     * @throws RuleParserException
     */
    public function testAValueThatDoesNotOpenWithAQuoteIsNotChecked(): void
    {
        $rule = (new RuleParser())->parseRule('alert http any any -> any any (reference:url,"example.com/a.php?id=1"; sid:9;)');

        $this->assertSame('url,"example.com/a.php?id=1"', $rule->options[0]->value);
        $this->assertSame(9, $rule->getSid());
    }

    public function testAnEscapedClosingQuoteLeavesTheValueOpen(): void
    {
        $this->expectException(RuleParserException::class);
        $this->expectExceptionMessage("Unterminated quoted value in option 'msg'");

        (new RuleParser())->parseRule('alert tcp any any -> any any (msg:"a\"; sid:1;)');
    }

    /**
     * An escaped backslash right before the closing quote (seen in ET Open) still closes the value.
     *
     * @throws RuleParserException
     */
    public function testAnEscapedBackslashBeforeTheClosingQuoteClosesTheValue(): void
    {
        $rule = (new RuleParser())->parseRule('alert smtp any any -> any any (content:"x-config|3a 20|\\\\"; sid:7;)');

        $this->assertSame('"x-config|3a 20|\\\\"', $rule->options[0]->value);
        $this->assertSame(7, $rule->getSid());
    }

    /**
     * @throws RuleParserException
     */
    public function testAColonInAValueIsNotANameSeparator(): void
    {
        $parser = new RuleParser();
        $rule = $parser->parseRule('alert http any any -> any any (msg:"GET http://x"; reference:url,http://example.com/a:b; sid:5;)');

        $this->assertSame('reference', $rule->options[1]->name);
        $this->assertSame('url,http://example.com/a:b', $rule->options[1]->value);
        $this->assertSame(5, $rule->getSid());
    }

    public function testOptionsEndingInAnEscapedSemicolonAreUnterminated(): void
    {
        $parser = new RuleParser();

        $this->expectException(RuleParserException::class);
        $this->expectExceptionMessage("Options must end with ';'");

        $parser->parseRule('alert tcp any any -> any any (sid:1; msg:"x\;)');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function duplicatedOptions(): array
    {
        return [
            'sid' => ['sid:1; sid:2;'],
            'rev' => ['sid:1; rev:1; rev:2;'],
            'gid' => ['sid:1; gid:1; gid:3;'],
            'msg' => ['msg:"a"; sid:1; msg:"b";'],
            'classtype' => ['sid:1; classtype:a; classtype:b;'],
            'priority' => ['sid:1; priority:1; priority:2;'],
        ];
    }

    #[DataProvider('duplicatedOptions')]
    public function testRejectsAnOptionThatSuricataAcceptsOnlyOnce(string $options): void
    {
        $parser = new RuleParser();

        $this->expectException(RuleParserException::class);
        $this->expectExceptionMessage('Duplicated');

        $parser->parseRule("alert tcp any any -> any any ({$options})");
    }

    /**
     * @throws RuleParserException
     */
    public function testRepeatableOptionsMayRepeat(): void
    {
        $parser = new RuleParser();
        $rule = $parser->parseRule('alert tcp any any -> any any (content:"a"; content:"b"; metadata:x 1; metadata:y 2; sid:1;)');

        $this->assertCount(5, $rule->options);
        $this->assertInstanceOf(Metadata::class, $rule->options[2]->value);
    }

    public function testRejectsAnInvalidOptionName(): void
    {
        $parser = new RuleParser();

        $this->expectException(RuleParserException::class);
        $this->expectExceptionMessage('Invalid option name');

        $parser->parseRule('alert tcp any any -> any any ("sid":1;)');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function actions(): array
    {
        return array_combine(RuleParser::ACTIONS, array_map(static fn (string $action): array => [$action], RuleParser::ACTIONS));
    }

    /**
     * @throws RuleParserException
     */
    #[DataProvider('actions')]
    public function testParsesEveryAction(string $action): void
    {
        $rule = (new RuleParser())->parseRule("{$action} tcp any any -> any any (sid:1;)");

        $this->assertNotNull($rule);
        $this->assertSame($action, $rule->getAction());
    }

    public function testOneMalformedRuleDoesNotStopTheOthers(): void
    {
        $parser = new RuleParser();

        $result = $parser->parseRules([
            10 => 'alert tcp any any -> any any (sid:1;)',
            11 => 'alert tcp any any -> any any (sid:2)',
            12 => 'not a rule',
            13 => 'alert tcp any any -> any any (msg:"x; sid:9;"; sid:3;)',
            14 => 'alert tcp any any -> any any (sid:4;)',
        ]);

        $this->assertSame([1, 4], array_map(static fn ($rule): ?int => $rule->getSid(), $result->getRules()));
        $this->assertTrue($result->hasErrors());
        $this->assertSame([11, 13], array_keys($result->getErrors()));
        $this->assertSame('alert tcp any any -> any any (msg:"x; sid:9;"; sid:3;)', $result->getErrors()[13]->getRule());
    }

    /**
     * @throws RuleParserException
     */
    public function testFileErrorsAreKeyedByLineNumber(): void
    {
        $filePath = tempnam(sys_get_temp_dir(), 'rules');
        file_put_contents($filePath, implode("\n", [
            '# a comment',
            'alert tcp any any -> any any (sid:1;)',
            '',
            'alert tcp any any -> any any (sid:2)',
            'alert tcp any any -> any any (sid:3;)',
        ]));

        try {
            $result = (new RuleParser())->parseFile($filePath);
        } finally {
            unlink($filePath);
        }

        $this->assertCount(2, $result->getRules());
        $this->assertSame([4], array_keys($result->getErrors()));
    }

    public function testAMissingFileThrows(): void
    {
        $this->expectException(RuleParserException::class);

        (new RuleParser())->parseFile(sys_get_temp_dir().'/does-not-exist-'.uniqid().'.rules');
    }

    public function testAPcreFailureIsReportedNotTakenForANonRule(): void
    {
        $backtrackLimit = ini_get('pcre.backtrack_limit');
        $jit = ini_get('pcre.jit');
        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', '1');

        try {
            $this->expectException(RuleParserException::class);
            $this->expectExceptionMessage('Rule pattern failed');

            (new RuleParser())->parseRule('alert tcp any any -> any any (msg:"'.str_repeat('a', 1000).'"; sid:1;)');
        } finally {
            ini_set('pcre.backtrack_limit', (string) $backtrackLimit);
            ini_set('pcre.jit', (string) $jit);
        }
    }
}
