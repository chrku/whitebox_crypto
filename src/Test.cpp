//
// Created by Christoph Kummer on 26.02.19.
//

#include <cassert>
#include <iomanip>
#include <iostream>

#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <cryptopp/osrng.h>

#include <RandomPermutation.h>
#include <WhiteBoxInterpreter.h>
#include <WhiteBoxTableGenerator.h>

// This file mostly includes test vectors to ensure
// that the implementation works as expected

namespace WhiteBox {
void test_vectors_unprotected();

void test_vectors_protected();

void test_vectors_mixing();

void test_vectors_protected_mixing();

void test_vectors_unprotected_decryption();

void test_vectors_mixing_decryption();

void test_vectors_protected_decryption();

void test_vectors_protected_mixing_decryption();

bool run_test_vector_unprotected(const std::string &plain,
                                 const std::string &key,
                                 const std::string &cipher) {
  State state;
  State key_state;
  State cipher_state;
  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> encryption_table(
        new WhiteBoxTableGenerator(key_state, false, false));
    std::unique_ptr<WhiteBoxData> encryption_data(
        encryption_table->getEncryptionTable());

    State result_encryption =
        interpret_white_box(*encryption_data, state, false);
    return result_encryption == cipher_state;
  }

  return false;
}

bool run_test_vector_protected(const std::string &plain, const std::string &key,
                               const std::string &cipher) {
  State state;
  State key_state;
  State cipher_state;
  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> encryption_table(
        new WhiteBoxTableGenerator(key_state, true, false));
    std::unique_ptr<WhiteBoxData> encryption_data(
        encryption_table->getEncryptionTable());

    State result_encryption =
        interpret_white_box(*encryption_data, state, false);
    return result_encryption == cipher_state;
  }

  return false;
}

bool run_test_vector_mixing(const std::string &plain, const std::string &key,
                            const std::string &cipher) {
  State state;
  State key_state;
  State cipher_state;

  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> encryption_table(
        new WhiteBoxTableGenerator(key_state, false, true));
    std::unique_ptr<WhiteBoxData> encryption_data(
        encryption_table->getEncryptionTable());

    State result_encryption =
        interpret_white_box(*encryption_data, state, false);
    return result_encryption == cipher_state;
  }

  return false;
}

bool run_test_vector_protected_mixing(const std::string &plain,
                                      const std::string &key,
                                      const std::string &cipher) {
  State state;
  State key_state;
  State cipher_state;

  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> encryption_table(
        new WhiteBoxTableGenerator(key_state, true, true));
    std::unique_ptr<WhiteBoxData> encryption_data(
        encryption_table->getEncryptionTable());

    State result_encryption =
        interpret_white_box(*encryption_data, state, false);
    return result_encryption == cipher_state;
  }

  return false;
}

bool run_test_vector_unprotected_decryption(const std::string &cipher,
                                            const std::string &key,
                                            const std::string &plain) {
  State state;
  State key_state;
  State cipher_state;

  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> decryption_table(
        new WhiteBoxTableGenerator(key_state, false, false));
    std::unique_ptr<WhiteBoxData> decryption_data(
        decryption_table->getDecryptionTable());

    State result_encryption =
        interpret_white_box(*decryption_data, cipher_state, true);
    return result_encryption == state;
  }

  return false;
}

bool run_test_vector_mixing_decryption(const std::string &cipher,
                                       const std::string &key,
                                       const std::string &plain) {
  State state;
  State key_state;
  State cipher_state;

  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> decryption_table(
        new WhiteBoxTableGenerator(key_state, false, true));
    std::unique_ptr<WhiteBoxData> decryption_data(
        decryption_table->getDecryptionTable());

    State result_encryption =
        interpret_white_box(*decryption_data, cipher_state, true);
    return result_encryption == state;
  }

  return false;
}

bool run_test_vector_protected_decryption(const std::string &cipher,
                                          const std::string &key,
                                          const std::string &plain) {
  State state;
  State key_state;
  State cipher_state;

  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> decryption_table(
        new WhiteBoxTableGenerator(key_state, true, false));
    std::unique_ptr<WhiteBoxData> decryption_data(
        decryption_table->getDecryptionTable());

    State result_encryption =
        interpret_white_box(*decryption_data, cipher_state, true);
    return result_encryption == state;
  }

  return false;
}

bool run_test_vector_protected_mixing_decryption(const std::string &cipher,
                                                 const std::string &key,
                                                 const std::string &plain) {
  State state;
  State key_state;
  State cipher_state;

  if (parse_aes_state(state, plain) && parse_aes_state(key_state, key) &&
      parse_aes_state(cipher_state, cipher)) {
    std::unique_ptr<WhiteBoxTableGenerator> decryption_table(
        new WhiteBoxTableGenerator(key_state, true, true));
    std::unique_ptr<WhiteBoxData> decryption_data(
        decryption_table->getDecryptionTable());

    State result_encryption =
        interpret_white_box(*decryption_data, cipher_state, true);
    return result_encryption == state;
  }

  return false;
}

void run_tests() {
  std::cout << "Running test vectors" << std::endl;

  // Run test vectors on unprotected Chow white box
  test_vectors_unprotected();
  test_vectors_protected();
  test_vectors_mixing();
  test_vectors_protected_mixing();

  // Decryption test vectors
  test_vectors_unprotected_decryption();
  test_vectors_protected_decryption();
  test_vectors_mixing_decryption();
  test_vectors_protected_mixing_decryption();
}

void test_vectors_protected_mixing_decryption() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: full white box decryption" << std::endl;
  has_succeeded = run_test_vector_protected_mixing_decryption(
      "29c3505f571420f6402299b31a02d73a", "5468617473206d79204b756e67204675",
      "54776f204f6e65204e696e652054776f");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected_mixing_decryption(
        "f5d3d58503b9699de785895a96fdbaaf", "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected_mixing_decryption(
        "43b1cd7f598ece23881b00e3ed030688", "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef");

  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

void test_vectors_protected_decryption() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: protected white box decryption" << std::endl;
  has_succeeded = run_test_vector_protected_decryption(
      "29c3505f571420f6402299b31a02d73a", "5468617473206d79204b756e67204675",
      "54776f204f6e65204e696e652054776f");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected_decryption(
        "f5d3d58503b9699de785895a96fdbaaf", "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected_decryption(
        "43b1cd7f598ece23881b00e3ed030688", "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef");

  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

void test_vectors_mixing_decryption() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: mixed white box decryption" << std::endl;
  has_succeeded = run_test_vector_mixing_decryption(
      "29c3505f571420f6402299b31a02d73a", "5468617473206d79204b756e67204675",
      "54776f204f6e65204e696e652054776f");
  if (has_succeeded)
    has_succeeded = run_test_vector_mixing_decryption(
        "f5d3d58503b9699de785895a96fdbaaf", "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51");
  if (has_succeeded)
    has_succeeded = run_test_vector_mixing_decryption(
        "43b1cd7f598ece23881b00e3ed030688", "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef");

  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

void test_vectors_unprotected_decryption() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: unprotected white box decryption" << std::endl;
  has_succeeded = run_test_vector_unprotected_decryption(
      "29c3505f571420f6402299b31a02d73a", "5468617473206d79204b756e67204675",
      "54776f204f6e65204e696e652054776f");
  if (has_succeeded)
    has_succeeded = run_test_vector_unprotected_decryption(
        "f5d3d58503b9699de785895a96fdbaaf", "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51");
  if (has_succeeded)
    has_succeeded = run_test_vector_unprotected_decryption(
        "43b1cd7f598ece23881b00e3ed030688", "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef");

  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

void test_vectors_protected_mixing() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: full white box" << std::endl;
  has_succeeded = run_test_vector_protected_mixing(
      "6bc1bee22e409f96e93d7e117393172a", "2b7e151628aed2a6abf7158809cf4f3c",
      "3ad77bb40d7a3660a89ecaf32466ef97");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected_mixing(
        "ae2d8a571e03ac9c9eb76fac45af8e51", "2b7e151628aed2a6abf7158809cf4f3c",
        "f5d3d58503b9699de785895a96fdbaaf");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected_mixing(
        "30c81c46a35ce411e5fbc1191a0a52ef", "2b7e151628aed2a6abf7158809cf4f3c",
        "43b1cd7f598ece23881b00e3ed030688");

  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

void test_vectors_mixing() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: mixed white box" << std::endl;
  has_succeeded = run_test_vector_mixing("6bc1bee22e409f96e93d7e117393172a",
                                         "2b7e151628aed2a6abf7158809cf4f3c",
                                         "3ad77bb40d7a3660a89ecaf32466ef97");
  if (has_succeeded)
    has_succeeded = run_test_vector_mixing("ae2d8a571e03ac9c9eb76fac45af8e51",
                                           "2b7e151628aed2a6abf7158809cf4f3c",
                                           "f5d3d58503b9699de785895a96fdbaaf");
  if (has_succeeded)
    has_succeeded = run_test_vector_mixing("30c81c46a35ce411e5fbc1191a0a52ef",
                                           "2b7e151628aed2a6abf7158809cf4f3c",
                                           "43b1cd7f598ece23881b00e3ed030688");
  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

// This is pretty ugly, but it works
void test_vectors_unprotected() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: unprotected white box" << std::endl;
  has_succeeded = run_test_vector_unprotected(
      "6bc1bee22e409f96e93d7e117393172a", "2b7e151628aed2a6abf7158809cf4f3c",
      "3ad77bb40d7a3660a89ecaf32466ef97");
  if (has_succeeded)
    has_succeeded = run_test_vector_unprotected(
        "ae2d8a571e03ac9c9eb76fac45af8e51", "2b7e151628aed2a6abf7158809cf4f3c",
        "f5d3d58503b9699de785895a96fdbaaf");
  if (has_succeeded)
    has_succeeded = run_test_vector_unprotected(
        "30c81c46a35ce411e5fbc1191a0a52ef", "2b7e151628aed2a6abf7158809cf4f3c",
        "43b1cd7f598ece23881b00e3ed030688");
  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}

void test_vectors_protected() {
  bool has_succeeded;
  std::cout << "Testing using predefined test vectors" << std::endl;
  std::cout << "Mode: protected white box" << std::endl;
  has_succeeded = run_test_vector_protected("6bc1bee22e409f96e93d7e117393172a",
                                            "2b7e151628aed2a6abf7158809cf4f3c",
                                            "3ad77bb40d7a3660a89ecaf32466ef97");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected(
        "ae2d8a571e03ac9c9eb76fac45af8e51", "2b7e151628aed2a6abf7158809cf4f3c",
        "f5d3d58503b9699de785895a96fdbaaf");
  if (has_succeeded)
    has_succeeded = run_test_vector_protected(
        "30c81c46a35ce411e5fbc1191a0a52ef", "2b7e151628aed2a6abf7158809cf4f3c",
        "43b1cd7f598ece23881b00e3ed030688");
  if (has_succeeded)
    std::cout << "Test vector success!" << std::endl;
  else
    std::cout << "Test vector failure!" << std::endl;
}
}  // namespace WhiteBox
