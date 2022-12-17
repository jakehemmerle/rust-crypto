// how the hell does just importing this add gcd support?
// answer: inside the lib.rs file, it calls gcd_impl! on the integer primitives
use gcd::Gcd;

#[derive(Debug, Default)]
pub struct PublicKey {
    pub e: u32,
    pub n: u32,
}

#[derive(Debug, Default)]
pub struct PrivateKey {
    pub d: u32,
    pub n: u32,
}

#[derive(Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

#[derive(PartialEq, Eq, Debug)]
pub struct Message(pub u32);

#[derive(PartialEq, Eq, Debug)]
pub struct CipherText(pub u32);

#[derive(PartialEq, Eq, Debug)]
pub struct Signature(pub u32);

pub enum Error {
    EncryptionError,
    DecryptionError,
    SignatureError,
    VerificationError,
}

impl Default for KeyPair {
    fn default() -> Self {
        KeyPair {
            public: PublicKey { e: 7, n: 33 },
            private: PrivateKey { d: 3, n: 33 },
        }
    }
}

impl KeyPair {
    /// simple example http://www.uobabylon.edu.iq/eprints/paper_1_17152_649.pdf
    pub fn new() -> KeyPair {
        // 1 make p, q random primes
        let p: u32 = 11;
        let q: u32 = 3;

        // 2 generate n
        let n: u32 = p * q;

        // euler's totient function finds the number of coprime numbers from 1 to it's input.
        // when a prime number is its input, the result is equivalent to (input - 1).
        // we need 'e' and 'd' to be coprime against eulers_totient(n)

        // not actually eulers function: a and b must be prime
        let eulers_totient = |a: u32, b: u32| (a - 1) * (b - 1);

        // what e and d must be coprime to
        let phi: u32 = eulers_totient(p, q);

        // 3) pick random d, that is coprime to (p-1)*(q-1)

        let d: u32 = 3;
        assert_eq!(d.gcd(phi), 1);

        // 4 generate e
        /*
        RATIONALE:
        We will want to compute e from d, p, and q, where e is the multiplicative inverse of d.

        EXAMPLE:
        Compute e such that ed ≡ 1 (mod phi)
        i.e. compute e = d-1 mod phi = 3-1 mod 20
        i.e. find a value for e such that phi divides (ed-1)
        i.e. find d such that 20 divides 3e-1.
        Simple testing (e = 1, 2, ...) gives e = 7
        */

        // is this equivalent to e*d == 1 mod phi?
        let multiplicitive_inverse = |d: u32, phi: u32| {
            // k can be any positive integer?
            let k = 1;
            let ed = (k * phi) + 1;
            ed / d
        };
        let e = multiplicitive_inverse(d, phi);
        assert_eq!(e.gcd(phi), 1);

        assert_eq!((e * d).gcd(phi), 1);

        KeyPair {
            public: PublicKey { e, n },
            private: PrivateKey { d, n },
        }
    }

    /// generate key from known e, d, and n
    pub fn new_from_values(e: u32, d: u32, n: u32) -> KeyPair {
        KeyPair {
            public: PublicKey { e, n },
            private: PrivateKey { d, n },
        }
    }
}

impl Message {
    pub fn encrypt(&self, recipient: &PublicKey) -> CipherText {
        CipherText(self.0.pow(recipient.e) % recipient.n)
    }
}

impl Signature {
    pub fn verify(&self, message: &Message, signer: &PublicKey) -> bool {
        let hopefully_message = self.0.pow(signer.e) % signer.n;
        message.0 == hopefully_message
    }
}

impl PrivateKey {
    pub fn decrypt(&self, ciphertext: &CipherText) -> Message {
        Message(ciphertext.0.pow(self.d) % self.n) // same as sign()
    }

    pub fn sign(&self, message: &Message) -> Signature {
        Signature(message.0.pow(self.d) % self.n) // same as decrypt()
    }
}
