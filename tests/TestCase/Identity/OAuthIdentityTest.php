<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Identity;

use Authentication\Identity;
use Authorization\AuthorizationService;
use Authorization\IdentityDecorator;
use Authorization\Policy\MapResolver;
use Cake\Http\ServerRequest;
use Cake\ORM\Entity;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenType;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\OAuthServer;
use DateTimeImmutable;

class OAuthIdentityTest extends TestCase
{
    private function validated(mixed $identity): ValidatedToken
    {
        $token = new Token('id', 'hash', TokenType::Access, 'f', null, '1', SubjectType::User, 'http://localhost/api', ['api'], new DateTimeImmutable());

        return new ValidatedToken(
            $token,
            new ResourceOwner('1', 'Ada', $identity),
            null,
            new ProtectedResource('http://localhost/api', 'API', ['api' => 'Use the API']),
            ['api'],
        );
    }

    public function testDelegatesToTheOwnersIdentity(): void
    {
        $entity = new Entity(['id' => 1, 'name' => 'Ada', 'role' => 'admin']);
        $identity = new OAuthIdentity($this->validated(new Identity($entity)));

        $this->assertSame(1, $identity->getIdentifier());
        $this->assertSame($entity, $identity->getOriginalData());
        $this->assertSame('admin', $identity['role']);
        $this->assertSame('Ada', $identity->name);
        $this->assertTrue(isset($identity['role']));
        $this->assertTrue($identity->hasScope('api'));
        $this->assertFalse($identity->hasScope('admin'));
    }

    public function testFallsBackToTheSubject(): void
    {
        $identity = new OAuthIdentity($this->validated(null));

        $this->assertSame('1', $identity->getIdentifier());
        $this->assertSame(['id' => '1'], $identity->getOriginalData());
    }

    public function testTheTokenIsReadableFromTheRequest(): void
    {
        $validated = $this->validated(['id' => 1]);
        $oauth = new OAuthIdentity($validated);
        $decorated = new IdentityDecorator(new AuthorizationService(new MapResolver()), $oauth);

        $this->assertSame($validated, OAuthServer::token((new ServerRequest())->withAttribute('identity', $oauth)));
        $this->assertSame($validated, OAuthServer::token((new ServerRequest())->withAttribute('identity', $decorated)));
        $this->assertNull(OAuthServer::token((new ServerRequest())->withAttribute('identity', new Identity(['id' => 1]))));
        $this->assertNull(OAuthServer::token(
            (new ServerRequest())->withAttribute('identity', new IdentityDecorator(new AuthorizationService(new MapResolver()), new Identity(['id' => 1]))),
        ));
        $this->assertNull(OAuthServer::token(new ServerRequest()));
    }
}
