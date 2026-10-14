<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The Lua hygiene guard: every script this repository ships must be
 * loadable by a modern Redis. Redis 7 and later reject a script that
 * assigns a global variable, answering "Attempt to modify a readonly
 * table". A bare `name = ...` at statement position is therefore a
 * runtime failure in production. No in-process test can see it, because
 * the test doubles interpret the Lua in PHP rather than executing it.
 *
 * This guard scans every `.lua` file and every `<<<'LUA'` heredoc of
 * the repository for a statement-position assignment to an identifier
 * that was never declared `local`, and fails when one exists. Table
 * constructor fields (`{ key = value }`) are not assignments and are
 * excluded by tracking the brace and paren depth: an assignment only
 * counts at depth zero.
 */
final class LuaScriptHygieneTest extends TestCase
{
    /**
     * Every bare-global assignment found, as `path:line: source`. Empty
     * when the repository is clean.
     *
     * @return list<string>
     */
    private function bareGlobals(): array
    {
        $root = \dirname(__DIR__, 5);
        $findings = [];
        foreach ($this->luaSources($root) as $path => $blocks) {
            foreach ($blocks as $block) {
                $lines = explode("\n", $block);
                $depth = 0;
                foreach ($lines as $index => $line) {
                    // A comment never assigns; the code before it may.
                    $code = (string) strstr($line, '--', true) === '' && str_contains($line, '--')
                        ? (string) strstr($line, '--', true)
                        : (str_contains($line, '--') ? (string) strstr($line, '--', true) : $line);
                    $stripped = trim($code);
                    $atDepthZero = $depth === 0;
                    if ($atDepthZero && preg_match('/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^=]/', $stripped, $m) === 1
                        && !preg_match('/^(local|if|for|while|return|function|elseif)\b/', $stripped)) {
                        $name = $m[1];
                        $declared = false;
                        for ($earlier = 0; $earlier < $index; $earlier++) {
                            if (preg_match('/^\s*local\s+[^=]*\b'.preg_quote($name, '/').'\b/', $lines[$earlier]) === 1) {
                                $declared = true;
                                break;
                            }
                        }
                        if (!$declared) {
                            $findings[] = sprintf('%s:%d: %s', $path, $index + 1, $stripped);
                        }
                    }
                    $depth += substr_count($code, '{') + substr_count($code, '(')
                        - substr_count($code, '}') - substr_count($code, ')');
                }
            }
        }
        sort($findings);

        return $findings;
    }

    /**
     * Every Lua source of the repository, keyed by its path relative to
     * the repository root: a `.lua` file is one block, a PHP file
     * contributes one block per `<<<'LUA'` heredoc.
     *
     * @return array<string, list<string>>
     */
    private function luaSources(string $root): array
    {
        $sources = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                static function (\SplFileInfo $file): bool {
                    return !\in_array($file->getFilename(), ['vendor', 'node_modules', 'target', 'var', 'test-results'], true);
                },
            ),
        );
        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                continue;
            }
            $path = $file->getPathname();
            $relative = ltrim(substr($path, \strlen($root)), '/');
            if (str_ends_with($path, '.lua')) {
                $sources[$relative] = [(string) file_get_contents($path)];

                continue;
            }
            if (!str_ends_with($path, '.php')) {
                continue;
            }
            $text = (string) file_get_contents($path);
            if (preg_match_all("/<<<'LUA'\n(.*?)\n\s*LUA;/s", $text, $matches) > 0) {
                $sources[$relative] = $matches[1];
            }
        }

        return $sources;
    }

    public function testTheScanActuallySeesTheRepositorysLua(): void
    {
        $sources = $this->luaSources(\dirname(__DIR__, 5));
        self::assertGreaterThan(
            10,
            \count($sources),
            'the hygiene scan must actually reach the shipped Lua (a scan that finds nothing proves nothing)',
        );
        $found = false;
        foreach ($sources as $path => $_) {
            if (str_contains($path, 'RedisStepUpChallengeStore.php')) {
                $found = true;
            }
        }
        self::assertTrue($found, 'the step-up store Lua must be inside the scan');
    }

    public function testNoLuaScriptAssignsABareGlobal(): void
    {
        $findings = $this->bareGlobals();
        self::assertSame(
            [],
            $findings,
            "A bare-global assignment makes a Lua script unloadable on Redis 7+ (readonly global table):\n".implode("\n", $findings),
        );
    }
}
