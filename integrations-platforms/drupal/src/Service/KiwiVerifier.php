<?php

declare(strict_types=1);

namespace Drupal\kiwicaptcha\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\kiwicaptcha\KiwiVerifyLogic;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

/**
 * The kiwicaptcha.verifier service: the pure logic plus the Drupal
 * HTTP client and the module configuration.
 */
class KiwiVerifier
{
    protected ClientInterface $httpClient;

    protected ConfigFactoryInterface $configFactory;

    public function __construct(ClientInterface $httpClient, ConfigFactoryInterface $configFactory)
    {
        $this->httpClient = $httpClient;
        $this->configFactory = $configFactory;
    }

    /**
     * The module settings as one array, the shape the pure logic and
     * the settings form share.
     *
     * @return array<string, mixed>
     */
    public function settings(): array
    {
        return (array) $this->configFactory->get('kiwicaptcha.settings')->getRawData();
    }

    /**
     * Verify one token for one scope.
     *
     * @param array<string, mixed> $server
     *
     * @return array{ok: bool, code: string}
     */
    public function verify(string $token, string $scope, array $server = []): array
    {
        return KiwiVerifyLogic::decide(
            $this->settings(),
            $token,
            $scope,
            $server,
            function (array $request): array {
                return $this->transport($request);
            }
        );
    }

    /**
     * The Guzzle transport: returns array{status: int, body: string}
     * and never throws.
     *
     * @param array{url: string, headers: array<string, string>, body: string} $request
     *
     * @return array{status: int, body: string}
     */
    protected function transport(array $request): array
    {
        try {
            $response = $this->httpClient->request('POST', $request['url'], [
                'headers' => $request['headers'],
                'body' => $request['body'],
                'timeout' => 5,
                'http_errors' => false,
                // The verify call must land on the configured endpoint
                // exactly: a 3xx from the network path can never
                // re-point it at a third party.
                'allow_redirects' => false,
            ]);
        } catch (GuzzleException $e) {
            return ['status' => 0, 'body' => ''];
        }

        return [
            'status' => $response->getStatusCode(),
            'body' => (string) $response->getBody(),
        ];
    }
}
