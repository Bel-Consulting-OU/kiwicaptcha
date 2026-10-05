<?php

declare(strict_types=1);

/**
 * The Joomla shim layer for the plugin tests: the tiny CMS surface
 * the captcha plugin touches. Loaded before the plugin file; nothing
 * here runs in Joomla itself.
 */

namespace Joomla\CMS\Plugin
{
    /**
     * The CMSPlugin shim: the params registry only.
     */
    class CMSPlugin
    {
        /**
         * @var object|null
         */
        protected $params;

        /**
         * @var object|null
         */
        protected $app;

        public function __construct($dispatcher = null, $params = null)
        {
            $this->params = $params;
        }

        /**
         * Test helper: inject the application shim.
         */
        public function setTestApp($app): void
        {
            $this->app = $app;
        }
    }
}

namespace Joomla\CMS
{
    /**
     * The Factory shim: a recording document.
     */
    class Factory
    {
        /**
         * @var object|null
         */
        public static $document;

        public static function getDocument()
        {
            return static::$document;
        }
    }

    /**
     * The document shim: records addScript calls.
     */
    class TestDocument
    {
        /**
         * @var list<array{url: string, attribs: array<string, mixed>}>
         */
        public array $scripts = [];

        public function addScript(string $url, array $attribs = [], array $options = []): TestDocument
        {
            $this->scripts[] = ['url' => $url, 'attribs' => $attribs];

            return $this;
        }
    }

    /**
     * The registry-ish params shim.
     */
    class TestParams
    {
        /**
         * @param array<string, mixed> $values
         */
        public function __construct(private array $values = [])
        {
        }

        public function get(string $key, $default = null)
        {
            return $this->values[$key] ?? $default;
        }
    }

    /**
     * The input shim: server and post holders with getRaw().
     */
    class TestInput
    {
        public object $server;

        public object $post;

        /**
         * @param array<string, mixed> $server
         * @param array<string, mixed> $post
         */
        public function __construct(array $server = [], array $post = [])
        {
            $this->server = new class($server) {
                private array $raw;
                public function __construct(array $raw)
                {
                    $this->raw = $raw;
                }
                public function getRaw(): array
                {
                    return $this->raw;
                }
            };
            $this->post = new class($post) {
                private array $raw;
                public function __construct(array $raw)
                {
                    $this->raw = $raw;
                }
                public function getRaw(): array
                {
                    return $this->raw;
                }
            };
        }
    }

    /**
     * The application shim.
     */
    class TestApplication
    {
        public object $input;

        public function __construct(array $server = [], array $post = [])
        {
            $this->input = new TestInput($server, $post);
        }
    }
}

namespace
{
    // The plugin file requires the Joomla bootstrap marker.
    if (!defined('JEXPORT')) {
        define('_JEXEC', '1');
    }
}
