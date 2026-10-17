<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\PrototypedArrayNode;

/**
 * The machine-checked feature inventory: every leaf the configuration
 * tree declares must either be read by the bundle at runtime (an anchor
 * string exists in a named source file) or be listed in the explicit
 * informational allowlist with the reason. A new node that nothing reads
 * fails this test instead of shipping as an inert feature.
 *
 * The default anchor is the quoted leaf name in the extension, where
 * nearly every knob is read. Leaves consumed indirectly (a parent array
 * passed whole, a prototype row handed to a builder, or a compile-time
 * tree validation) name their own file and anchor in readAnchors.
 */
final class FeatureUseTest extends TestCase
{
    private const EXTENSION = 'src/DependencyInjection/KiwiCaptchaExtension.php';

    /**
     * Leaves whose read is not a direct `'key'` lookup in the extension:
     * the anchor proves the named file consumes the value. Paths may end
     * in `.*` to cover a prototyped row's children.
     *
     * @var array<string, array{0: string, 1: string}>
     */
    private const readAnchors = [
        // The profile is selected through the layered-defaults helper.
        'protection_profile' => ['src/DependencyInjection/ProtectionProfileDefaults.php', "'protection_profile'"],
        // A compile-time safety valve read by the tree validation.
        'execution_allow_downgrade' => ['src/DependencyInjection/Configuration.php', "'execution_allow_downgrade'"],
        // The whole tables are passed to the store/policy builders.
        'risk.saturations' => [self::EXTENSION, "['saturations']"],
        'risk.weights' => [self::EXTENSION, "['weights']"],
        // Prototype rows handed whole to another consumer.
        'rsw_verification_keys.*' => [self::EXTENSION, "['rsw_verification_keys']"],
        'risk.scopes.*' => [self::EXTENSION, "['scopes']"],
        'risk.sitekeys.*' => [self::EXTENSION, "['sitekeys']"],
        'risk.agents.*' => ['src/Security/Agents/AgentDefinition.php', "'public_keys'"],
    ];

    /**
     * Declared leaves that are deliberately not read: the info text says
     * so. Keep this list short and exact; every entry needs a reason.
     *
     * @var array<string, string>
     */
    private const informational = [
        'risk.calibration.retention_secs' => 'accepted for backward compatibility with the former in-memory calibrator; the Redis-backed store uses the risk-v1 fixed 24 h window (the tree info says "informational")',
    ];

    public function testEveryDeclaredLeafIsReadAtRuntimeOrExplicitlyInformational(): void
    {
        $unread = [];
        foreach ($this->leaves() as $path => $node) {
            if (\array_key_exists($path, self::informational)) {
                self::assertNotSame('', self::informational[$path], 'the informational allowlist carries a reason for '.$path);
                continue;
            }
            [$file, $anchor] = $this->readAnchor($path);
            $contents = @file_get_contents(\dirname(__DIR__).'/'.$file);
            self::assertIsString($contents, 'the anchor file exists: '.$file);
            if (!str_contains($contents, $anchor)) {
                $unread[] = sprintf('%s (expected %s in %s)', $path, $anchor, $file);
            }
        }

        self::assertSame(
            [],
            $unread,
            "every declared configuration leaf must be read at runtime or listed in FeatureUseTest::informational:\n".implode("\n", $unread),
        );
    }

    public function testTheInformationalAllowlistOnlyHoldsNodesTheTreeCallsInformational(): void
    {
        foreach (self::informational as $path => $reason) {
            self::assertArrayHasKey($path, $this->leaves(), $path.' is a declared leaf');
            $info = $this->infoAlong($path);
            self::assertStringContainsString('informational', strtolower($info), $path.' is documented as informational by its info text');
        }
    }

    /**
     * @return array<string, BaseNode>
     */
    private function leaves(): array
    {
        $leaves = [];
        $this->walk((new Configuration())->getConfigTreeBuilder()->buildTree(), '', $leaves);

        return $leaves;
    }

    /**
     * @param array<string, BaseNode> $leaves
     */
    private function walk(BaseNode $node, string $path, array &$leaves): void
    {
        if ($node instanceof PrototypedArrayNode) {
            $prototype = $node->getPrototype();
            if ($prototype instanceof ArrayNode && $prototype->getChildren() !== []) {
                $this->walk($prototype, $path.'.*', $leaves);

                return;
            }
        }
        if (!$node instanceof ArrayNode || $node->getChildren() === []) {
            $leaves[$path] = $node;

            return;
        }
        foreach ($node->getChildren() as $name => $child) {
            $this->walk($child, $path === '' ? $name : $path.'.'.$name, $leaves);
        }
    }

    /**
     * The info text of the path's node and its ancestors: the tree states
     * cross-cutting semantics (the calibration window is informational)
     * on the parent and leaves the leaf's own info empty.
     */
    private function infoAlong(string $path): string
    {
        $node = (new Configuration())->getConfigTreeBuilder()->buildTree();
        $info = $node->getInfo() ?? '';
        foreach (explode('.', $path) as $segment) {
            if (!$node instanceof ArrayNode) {
                return $info;
            }
            $children = $node->getChildren();
            self::assertArrayHasKey($segment, $children, 'the tree exposes '.$segment.' under '.$path);
            $node = $children[$segment];
            $info .= ' '.($node->getInfo() ?? '');
        }

        return $info;
    }

    /**
     * @return array{0: string, 1: string} file (relative to the bundle root) and anchor string
     */
    private function readAnchor(string $path): array
    {
        foreach (self::readAnchors as $prefix => [$file, $anchor]) {
            if ($path === $prefix || str_starts_with($path, $prefix.'.')) {
                return [$file, $anchor];
            }
        }

        $position = strrpos($path, '.');
        $segment = $position === false ? $path : substr($path, $position + 1);

        return [self::EXTENSION, "'".$segment."'"];
    }
}
