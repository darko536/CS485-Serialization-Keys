/*
 * @file  demo-simple-example.cpp - Simple demo for BFVrns with serialization.
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "palisade.h"
#include <fstream>

// header files needed for serialization
#include "utils/serialize-binary.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main()
{
  #ifdef NO_QUADMATH
  std::cout << "This demo uses BFVrns which is currently not available for this architecture"<<std::endl;
  exit(0);
#endif
    // Sample Program: Step 1 � Set CryptoContext

	// Set the main parameters
	int plaintextModulus = 65537;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;

	// Instantiate the crypto context
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

	// Enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	cout << "\nThe cryptocontext has been generated." << std::endl;
	
	if (!Serial::SerializeToFile(DATAFOLDER + "/testing.txt", "TESTING", SerType::BINARY)){
		cerr << "Error writing serialization pf the crypto context to cryptocontext.txt" << endl;
		return 1;
	}
	else
	{
		cout << "\nThe word \"TESTING\" has been serialized into testing.txt" << std::endl;
		std::ifstream in_file(DATAFOLDER+"/testing.txt", std::ios::binary | std::ios::ate);
		cout << "The file size of the word \"TESTING\" is " << in_file.tellg() << " bytes" << std::endl;
	}

	// Serialize cryptocontext
	if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
		cerr << "Error writing serialization of the crypto context to cryptocontext.txt" << endl;
		return 1;
	}
	else
	{
		cout << "\nThe cryptocontext has been serialized." << std::endl;
		std::ifstream in_file(DATAFOLDER+"/cryptocontext.txt", std::ios::binary | std::ios::ate);
		cout << "The file size of the cryptocontext is " << in_file.tellg() << " bytes" << std::endl;
	}
	// Deserialize the crypto context
	CryptoContext<DCRTPoly> cc;
	if ( !Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY) ) {
		cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << endl;
		return 1;
	}
	else
		cout << "\nThe cryptocontext has been deserialized." << std::endl;

	//Sample Program: Step 2 � Key Generation

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	// Generate a public/private key pair
	keyPair = cc->KeyGen();

	cout << "\nThe key pair has been generated." << std::endl;

	cout << "The key pair is : " << keyPair.publicKey << std::endl;

	// Serialize the public key
	if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
		cerr << "Error writing serialization of public key to key-public.txt" << endl;
		return 1;
	}
	else
	{
		cout << "\nThe public key has been serialized." << std::endl;
		std::ifstream in_file(DATAFOLDER+"/key-public.txt", std::ios::binary | std::ios::ate);
		cout << "The file size of the serialized public key is " << in_file.tellg() << " bytes" << std::endl;
	}

	// Serialize the secret key
	if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
		cerr << "Error writing serialization of private key to key-private.txt" << endl;
		return 1;
	}
	else
	{
		cout << "\nThe secret key has been serialized." << std::endl;
		std::ifstream in_file(DATAFOLDER+"/key-private.txt", std::ios::binary | std::ios::ate);
		cout << "The file size of the serialized secret key is " << in_file.tellg() << " bytes" << std::endl;
	}


	LPPublicKey<DCRTPoly> pk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
		cerr << "Could not read public key" << endl;
		return 1;
	}
	else
	{
		cout << "\nThe public key has been deserialized." << std::endl;
		std::ifstream in_file(DATAFOLDER+"/key-public.txt", std::ios::binary | std::ios::ate);
		cout << "The file size of the deserialized public key is " << in_file.tellg() << " bytes" << std::endl;
	}


	LPPrivateKey<DCRTPoly> sk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", sk, SerType::BINARY) == false) {
		cerr << "Could not read secret key" << endl;
		return 1;
	}
	else
	{
		cout << "\nThe secret key has been deserialized." << std::endl;
		std::ifstream in_file(DATAFOLDER+"/key-private.txt", std::ios::binary | std::ios::ate);
		cout << "The file size of the deserialized private key is " << in_file.tellg() << " bytes" << std::endl;
	}

	return 0;
}
