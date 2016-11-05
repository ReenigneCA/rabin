struct buffer1024{
	uint8_t values[128];
}

class rabinPublicKey{
  BIGNUM n;
void encrypt(buffer1024 * plainText,buffer1024 * cipherText);
}

class rabinPrivateKey{
	BIGNUM p,q,n;
void decrypt(buffer1024 * cipherText, buffer1024 * arrayOf4Solutions);

}
