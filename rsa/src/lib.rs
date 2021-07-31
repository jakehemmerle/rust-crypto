mod rsa;

#[cfg(test)]
mod test {
    use crate::rsa::*;

    #[test]
    fn test_test() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_create_key() {
        let key = KeyPair::new();
        // why does this not print since I've added Debug for KeyPair and its structs?
        println!("{:?}", key);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = KeyPair::default();
        
        let message: Message = Message(7u32);
        let ciphertext = message.encrypt(&key.public);
        assert_eq!(ciphertext, CipherText(28));
        let decrypted_message = key.private.decrypt(&ciphertext);

        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn test_sign_verify() {
        let signer = KeyPair::default();
        let message = Message(8);

        let signature = signer.private.sign(&message);

        assert_eq!(signature.verify(&message, &signer.public), true);

    }

    #[test]
    fn test_dh() {
        let key = KeyPair::default();
        let key2 = KeyPair::new_from_values(13u32, 37u32, 60u32);
    }

}