<?php

declare(strict_types=1);

namespace LaminasTest\Crypt\PublicKey;

use Laminas\Crypt\Exception;
use Laminas\Crypt\PublicKey\DiffieHellman;
use Laminas\Math\BigInteger;
use Laminas\Math\Exception\RuntimeException as MathException;
use PHPUnit\Framework\TestCase;

use function hex2bin;
use function str_contains;

/**
 * @group      Laminas_Crypt
 */
class DiffieHellmanTest extends TestCase
{
    public function setUp(): void
    {
        try {
            BigInteger\BigInteger::factory();
        } catch (MathException $e) {
            if (str_contains($e->getMessage(), 'math support is not detected')) {
                $this->markTestSkipped($e->getMessage());
            } else {
                throw $e;
            }
        }
    }

    public function testWithSpec(): void
    {
        $aliceOptions = [
            'prime'     => '563',
            'generator' => '5',
            'private'   => '9',
        ];
        $bobOptions   = [
            'prime'     => '563',
            'generator' => '5',
            'private'   => '14',
        ];

        DiffieHellman::useOpensslExtension(false);
        $alice = new DiffieHellman($aliceOptions['prime'], $aliceOptions['generator'], $aliceOptions['private']);
        $bob   = new DiffieHellman($bobOptions['prime'], $bobOptions['generator'], $bobOptions['private']);

        $alice->generateKeys();
        $bob->generateKeys();

        $this->assertEquals('78', $alice->getPublicKey());
        $this->assertEquals('534', $bob->getPublicKey());

        $aliceSecretKey = $alice->computeSecretKey($bob->getPublicKey());
        $bobSecretKey   = $bob->computeSecretKey($alice->getPublicKey());

        // both Alice and Bob should now have the same secret key
        $this->assertEquals('117', $aliceSecretKey);
        $this->assertEquals('117', $bobSecretKey);
    }

    public function testWithBinaryFormsAndLargeIntegers(): void
    {
        // @codingStandardsIgnoreStart
        $aliceOptions = [
            'prime'    => '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443',
            'generator'=> '2',
            'private'  => '99209314066572595236408569591967988557141249561494267486251808035535396332278620143536317681312712891672623072630995180324388841681491857745515696789091127409515009250358965816666146342049838178521379132153348139908016819196219448310107072632515749339055798122538615135104828702523796951800575031871051678091'
        ];
        $bobOptions   = [
            'prime'    => '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443',
            'generator'=> '2',
            'private'  => '33411735792639558625733635717892563612548180650402161151077478314841463707948899786103588912325634730410551946772752880177868972816963551821740386700076034213408153924692562543117963464733156600545484510833072427003474207064650714831083304497737160382097083356876078146231616972608703322302585471319261275664'
        ];

        DiffieHellman::useOpensslExtension(false);

        $alice = new DiffieHellman($aliceOptions['prime'], $aliceOptions['generator'], $aliceOptions['private']);
        $bob   = new DiffieHellman($bobOptions['prime'], $bobOptions['generator'], $bobOptions['private']);

        $alice->generateKeys();
        $bob->generateKeys();

        //ANA5iVHvXa9NqQLVaBsix3Qvq3wVN5gwnpShj10QxR6H8ephXzdoHGQpqf2m+Hsw136SATmraVXW59n0zVBqOuA7ShNlhk7GQpfdEYKxlL/F1v+Fgz13hO4ObuylhwRvywhOfl7IpROT+fxiMqq/YLIrnU5pPh/4YmGLaminasUpmq/ZN
        $this->assertEquals(
            '0DmJUe9dr02pAtVoGyLHdC+rfBU3mDCelKGPXRDFHofx6mFfN2gcZCmp/ab4ezDXfpIBOatpVdbn2fTNUGo64DtKE2WGTsZCl90RgrGUv8XW/4WDPXeE7g5u7KWHBG/LCE5+XsilE5P5/GIyqr9gsiudTmk+H/hiYZl9Smar9k0=',
            base64_encode($alice->getPublicKey(DiffieHellman::FORMAT_BINARY))
        );

        //AL/KbggWh3XIdLLcZpMkv7Gb2R8geX9AFZKKQEOcCkmSMhBx3Bp+w11x9ruFnQi/pDK/AXEacUQSdEw8H2T6bud5xTRI1HfNVpX2ipPeXuGvwwuHYZXwZEDHm5XqG4XnUDxQKOxfUpBze7ky2v4JcRvt0/Q02/opHDlT6B9wNRuo
        $this->assertEquals(
            'v8puCBaHdch0stxmkyS/sZvZHyB5f0AVkopAQ5wKSZIyEHHcGn7DXXH2u4WdCL+kMr8BcRpxRBJ0TDwfZPpu53nFNEjUd81WlfaKk95e4a/DC4dhlfBkQMebleobhedQPFAo7F9SkHN7uTLa/glxG+3T9DTb+ikcOVPoH3A1G6g=',
            base64_encode($bob->getPublicKey(DiffieHellman::FORMAT_BINARY))
        );

        $aliceSecretKey = $alice->computeSecretKey(
            $bob->getPublicKey(DiffieHellman::FORMAT_BINARY),
            DiffieHellman::FORMAT_BINARY,
            DiffieHellman::FORMAT_BINARY
        );
        $bobSecretKey   = $bob->computeSecretKey(
            $alice->getPublicKey(DiffieHellman::FORMAT_BINARY),
            DiffieHellman::FORMAT_BINARY,
            DiffieHellman::FORMAT_BINARY
        );

        // both Alice and Bob should now have the same secret key
        $expectedSharedSecret = base64_decode('FAAkw7NN1+raX9K1+dR3nqX2LZcDYYuZH13lpasaDIM4/ZXqbzdgiHZ86SILN27BjmJObtNQG/SNHfhxMalLMtLv+v0JFte/6+pIvMG9tAoPFsVh2BAvBuNpLY5W5gusgQ2p4pvJK0wz9YJ8iFdOHEOnhzYuN7LS/YXx2rBOz0Q=');

        $this->assertEquals($expectedSharedSecret, $aliceSecretKey);
        $this->assertEquals($expectedSharedSecret, $bobSecretKey);

        // @codingStandardsIgnoreEnd
    }

    public function testWithBinaryFormsAndLargeIntegersAndOpensslWithoutPrivateKey(): void
    {
        // @codingStandardsIgnoreStart
        // skip this test if openssl DH support is not available
        if (!function_exists('openssl_dh_compute_key')) {
            $this->markTestSkipped(
                'An openssl extension with Diffie-Hellman support is not available.'
            );
        }

        DiffieHellman::useOpensslExtension(true);

        $aliceOptions = [
            'prime'    => '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443',
            'generator'=> '2'
        ];
        $bobOptions   = [
            'prime'    => '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443',
            'generator'=> '2'
        ];

        $alice = new DiffieHellman($aliceOptions['prime'], $aliceOptions['generator']);
        $bob   = new DiffieHellman($bobOptions['prime'], $bobOptions['generator']);

        $alice->generateKeys();
        $bob->generateKeys();

        $this->assertNotEquals($alice->getPublicKey(), $bob->getPublicKey());
        $this->assertNotEquals($alice->getPrivateKey(), $bob->getPrivateKey());

        $aliceSecretKey = $alice->computeSecretKey(
            $bob->getPublicKey(DiffieHellman::FORMAT_BINARY),
            DiffieHellman::FORMAT_BINARY,
            DiffieHellman::FORMAT_BINARY
        );
        $bobSecretKey   = $bob->computeSecretKey(
            $alice->getPublicKey(DiffieHellman::FORMAT_BINARY),
            DiffieHellman::FORMAT_BINARY,
            DiffieHellman::FORMAT_BINARY
        );

        $this->assertNotEmpty($aliceSecretKey);
        $this->assertEquals($aliceSecretKey, $bobSecretKey);

        // @codingStandardsIgnoreEnd
    }

    public function testGenerateKeysWithUnsetPrivateKey(): void
    {
        $dh = new DiffieHellman(
            // This number was derived from a prime found in the PHP manual
            // phpcs:ignore Generic.Files.LineLength.TooLong
            '20595147743956561473635506785364689242608156641683669610631810376381034689091062076699156642251004392108952858143484774920291169240754614150220808705672513182725720799259477027420213618077724812926858890986423862521124832721602613093351849581066146191024215917126835618245457407314890365423196085851324526812966877725950802151696434289308856332532106388538037192731883124146318902069590087059811604115285813365981576703499840166093799061116445367741724816239106013192273120668831654534518856490326103748487603609919471960894332833324295672569077878683980560262697833730582706235817119832357244970862344795976907973227',
            '2'
        );
        $dh->generateKeys();
        $privateKey = $dh->getPrivateKey();
        $this->assertNotNull($privateKey);
    }

    public function testInitMathBeforeAnyConversion(): void
    {
        $this->expectNotToPerformAssertions();

        // try different format of private key
        new DiffieHellman('563', '5', '9', DiffieHellman::FORMAT_NUMBER);
        new DiffieHellman('563', '5', hex2bin('09'), DiffieHellman::FORMAT_BINARY);
    }

    public function testGetPublicKeyWithoutGenerated(): void
    {
        $dh = new DiffieHellman('563', '5');

        $this->expectException(Exception\InvalidArgumentException::class);
        $dh->getPublicKey();
    }

    public function testSetWrongPublicKey(): void
    {
        $dh = new DiffieHellman('563', '5');

        $this->expectException(Exception\InvalidArgumentException::class);
        $dh->setPublicKey('-2');
    }

    public function testGetSharedSecretKeyWihoutCompute(): void
    {
        $dh = new DiffieHellman('563', '5');

        $this->expectException(Exception\InvalidArgumentException::class);
        $dh->getSharedSecretKey();
    }

    public function testSetWrongPrime(): void
    {
        $dh = new DiffieHellman('563', '5');

        $this->expectException(Exception\InvalidArgumentException::class);
        $dh->setPrime('-2');
    }

    public function testSetWrongGenerator(): void
    {
        $dh = new DiffieHellman('563', '5');

        $this->expectException(Exception\InvalidArgumentException::class);
        $dh->setGenerator('-2');
    }

    public function testSetWrongPrivateKey(): void
    {
        $dh = new DiffieHellman('563', '5');

        $this->expectException(Exception\InvalidArgumentException::class);
        $dh->setPrivateKey('-2');
    }
}
