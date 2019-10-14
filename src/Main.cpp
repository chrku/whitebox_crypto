
//
// Created by Christoph Kummer on 26.02.19.
//

#include <memory>
#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/program_options.hpp>
#include <boost/serialization/array.hpp>

#include <Test.h>
#include <WhiteBoxInterpreter.h>
#include <WhiteBoxTableGenerator.h>
#include <ExternalEncoding.h>

void create_encryption_tables(std::ofstream &ofstream, WhiteBox::State key, bool code,
  WhiteBox::ExternalEncoding* input_encoding, WhiteBox::ExternalEncoding* output_encoding);

void create_decryption_tables(std::ofstream &ofstream, WhiteBox::State key, bool code,
  WhiteBox::ExternalEncoding* input_encoding, WhiteBox::ExternalEncoding* output_encoding);

void encrypt(WhiteBox::WhiteBoxData &data, const WhiteBox::State &iv,
             std::istream &istream, std::ostream &ostream,
             WhiteBox::BlockCipherMode mode, WhiteBox::PaddingMode padding);

void decrypt(WhiteBox::WhiteBoxData &data, const WhiteBox::State &iv,
             std::istream &istream, std::ostream &ostream,
             WhiteBox::BlockCipherMode mode, WhiteBox::PaddingMode padding);

/*! \brief Entry point to the application
 *  \param argc command line parameters
 *  \param argv command line parameters
 */
int main(int argc, const char *argv[]) {
  // Maps for parsing mode of operation and padding
  std::map<std::string, WhiteBox::BlockCipherMode> mode_map =
      boost::assign::map_list_of("ECB", WhiteBox::BlockCipherMode::ECB)(
          "CBC", WhiteBox::BlockCipherMode::CBC)(
          "CTR", WhiteBox::BlockCipherMode::CTR);

  std::map<std::string, WhiteBox::PaddingMode> padding_map =
      boost::assign::map_list_of("NONE", WhiteBox::PaddingMode::NONE)(
          "ZEROS", WhiteBox::PaddingMode::ZEROS)("PKCS",
                                                 WhiteBox::PaddingMode::PKCS)(
          "ONE_AND_ZEROS", WhiteBox::PaddingMode::ONE_AND_ZEROS);

  boost::program_options::options_description command_line_options;

  // Command line parsing
  // Since this is going to be complex, I decided to use the boost library for
  // this
  command_line_options.add_options()("help", "Shows usage")(
      "create-encryption-tables", boost::program_options::value<std::string>(),
      "Create encryption table in given file")(
      "create-decryption-tables", boost::program_options::value<std::string>(),
      "Create decryption table in given file")
      ("create-c-file", "Create valid C code for use in another program")
      (
      "key", boost::program_options::value<std::string>(),
      "AES Key used for encryption/decryption, hexadecimal format")(
      "whitebox-table", boost::program_options::value<std::string>(),
      "Load given white box table")(
      "set-mode", boost::program_options::value<std::string>(),
      "Set block cipher mode, either ECB, CBC or CTR, default CBC")(
      "iv", boost::program_options::value<std::string>(),
      "Set initialization vector")(
      "set-padding", boost::program_options::value<std::string>(),
      "Set padding mode, either NONE, ZEROS, PKCS or ONE_AND_ZEROS, default "
      "PKCS")(
      "decrypt",
      "Pass this to decrypt, given key, mode, iv and output/input files")(
      "encrypt",
      "Pass this to decrypt, given key, mode, iv and output/input files")(
      "input-file", boost::program_options::value<std::string>(),
      "File to read input from, stdin if absent, used for block cipher "
      "operations")("output-file", boost::program_options::value<std::string>(),
                    "File to write output to, stdout if absent, used for block "
                    "cipher operations")("test", "Run predefined test output")
                    ("encrypt-state", boost::program_options::value<std::string>(),
                            "Encrypt given state, output ciphertext to stdout")
    ("create-external-encoding", boost::program_options::value<std::string>(),
      "Create external encodings in given file")
    ("apply-input-encoding", boost::program_options::value<std::string>(),
      "Apply input encoding to whitebox")
    ("apply-output-encoding", boost::program_options::value<std::string>(),
      "Apply output encoding to whitebox");

  boost::program_options::variables_map variables;
  try {
    auto parsed_options = parse_command_line(argc, argv, command_line_options);
    store(parsed_options, variables);
  } catch (boost::program_options::error &e) {
    std::cerr << e.what() << std::endl;
    return -1;
  }

  // Handle command line options

  // Display help
  if (variables.empty() || variables.count("help")) {
    std::cout << "Usage: " << std::endl;
    std::cout << command_line_options << std::endl;
    return 0;
  }

  if (variables.count("test")) {
    WhiteBox::run_tests();
    return 0;
  }

  if (variables.count("encrypt") && variables.count("decrypt")) {
    std::cerr << "Cannot encrypt and decrypt at the same time" << std::endl;
    return -1;
  }

  bool has_key = false;
  bool has_iv = false;
  bool has_table = false;
  bool has_encryption_table_file = false;
  bool has_decryption_table_file = false;
  bool has_input_file = false;
  bool has_output_file = false;
  bool create_code = false;
  bool has_input_encoding = false;
  bool has_output_encoding = false;

  // Parse all the relevant values
  WhiteBox::State key;
  WhiteBox::State iv;

  WhiteBox::WhiteBoxData whitebox_table{};

  std::ofstream encryption_table_output;
  std::ofstream decryption_table_output;
  std::ifstream input_file;
  std::ofstream output_file;

  WhiteBox::BlockCipherMode block_cipher_mode;
  WhiteBox::PaddingMode padding_mode;

  CryptoPP::AutoSeededRandomPool rng;

  WhiteBox::ExternalEncoding input_encoding(rng);
  WhiteBox::ExternalEncoding output_encoding(rng);

  if (variables.count("create-c-file")) {
    create_code = true;
  }

  if (variables.count("create-external-encoding")) {
    std::string path = variables["create-external-encoding"].as<std::string>();
    std::ofstream ofs(path);
    if (ofs.good()) {
      boost::archive::text_oarchive text_oarchive(ofs);
      WhiteBox::ExternalEncoding enc(rng);
      text_oarchive << enc;
    } else {
      std::cerr << "Could not create encoding in given file" << std::endl;
      return -1;
    }
  }

  if (variables.count("apply-input-encoding")) {
    std::string path = variables["apply-input-encoding"].as<std::string>();
    std::ifstream ifs(path);
    if (ifs.good()) {
      boost::archive::text_iarchive text_iarchive(ifs);
      text_iarchive >> input_encoding;
      has_input_encoding = true;
    } else {
      std::cerr << "Could not load input encoding";
      return -1;
    }
  }

  if (variables.count("apply-output-encoding")) {
    std::string path = variables["apply-output-encoding"].as<std::string>();
    std::ifstream ifs(path);
    if (ifs.good()) {
      boost::archive::text_iarchive text_iarchive(ifs);
      text_iarchive >> output_encoding;
      has_output_encoding = true;
    } else {
      std::cerr << "Could not load output encoding";
      return -1;
    }
  }

  if (variables.count("key")) {
    if (!WhiteBox::parse_aes_state(key, variables["key"].as<std::string>())) {
      std::cerr << "Could not parse key" << std::endl;
      return -1;
    } else {
      has_key = true;
    }
  }

  if (variables.count("iv")) {
    if (!WhiteBox::parse_aes_state(iv, variables["iv"].as<std::string>())) {
      std::cerr << "Could not parse initialization vector" << std::endl;
      return -1;
    } else {
      has_iv = true;
    }
  }

  if (variables.count("whitebox-table")) {
    std::string path = variables["whitebox-table"].as<std::string>();
    std::ifstream ifs(path);
    if (ifs.good()) {
      boost::archive::text_iarchive text_iarchive(ifs);
      text_iarchive >> whitebox_table;
      if (has_input_encoding)
        input_encoding.applyToWhiteBox(&whitebox_table, true);
      if (has_output_encoding)
        output_encoding.applyToWhiteBox(&whitebox_table, false);
      has_table = true;
    } else {
      std::cerr << "Could not open white box table file" << std::endl;
      return -1;
    }
  }

  if (variables.count("create-encryption-tables")) {
    std::string path = variables["create-encryption-tables"].as<std::string>();
    encryption_table_output.open(path);
    if (!encryption_table_output.good()) {
      std::cerr << "Could not open encryption table output file" << std::endl;
      return -1;
    } else {
      has_encryption_table_file = true;
    }
  }

  if (variables.count("create-decryption-tables")) {
    std::string path = variables["create-decryption-tables"].as<std::string>();
    decryption_table_output.open(path);
    if (!decryption_table_output.good()) {
      std::cerr << "Could not open decryption table output file" << std::endl;
      return -1;
    } else {
      has_decryption_table_file = true;
    }
  }

  if (variables.count("input-file")) {
    std::string path = variables["input-file"].as<std::string>();
    input_file.open(path);
    if (!input_file.good()) {
      std::cerr << "Could not open input file" << std::endl;
      return -1;
    } else {
      has_input_file = true;
    }
  }

  if (variables.count("output-file")) {
    std::string path = variables["output-file"].as<std::string>();
    output_file.open(path);
    if (!output_file.good()) {
      std::cerr << "Could not open output file" << std::endl;
      return -1;
    } else {
      has_output_file = true;
    }
  }

  // Parse mode of operation and padding
  if (variables.count("set-mode")) {
    std::string mode = variables["set-mode"].as<std::string>();
    if (mode_map.count(mode)) {
      block_cipher_mode = mode_map[mode];
    } else {
      std::cerr << "Could not parse mode" << std::endl;
      return -1;
    }
  } else {
    block_cipher_mode = WhiteBox::BlockCipherMode::CBC;
  }

  if (variables.count("set-padding")) {
    std::string padding = variables["set-padding"].as<std::string>();
    if (padding_map.count(padding)) {
      padding_mode = padding_map[padding];
      if (block_cipher_mode == WhiteBox::BlockCipherMode::CTR && padding_mode != WhiteBox::PaddingMode::NONE) {
        std::cerr << "CTR does not use padding" << std::endl;
        return -1;
      }
    } else {
      std::cerr << "Could not parse padding" << std::endl;
      return -1;
    }
  } else {
    if (block_cipher_mode != WhiteBox::BlockCipherMode::CTR)
      padding_mode = WhiteBox::PaddingMode::PKCS;
    else
      padding_mode = WhiteBox::PaddingMode::NONE;
  }

  // Now, that parsing is complete, do the actions
  if (variables.count("create-encryption-tables")) {
    if (!has_key) {
      std::cerr << "Key needed for table creation" << std::endl;
      return -1;
    }
    if (!has_encryption_table_file) {
      std::cerr << "Missing encryption table file" << std::endl;
      return -1;
    }

    WhiteBox::ExternalEncoding* input = nullptr;
    WhiteBox::ExternalEncoding* output = nullptr;
    if (has_input_encoding)
      input = &input_encoding;
    if (has_output_encoding)
      output = &output_encoding;

    create_encryption_tables(encryption_table_output, key, create_code, input, output);
  }

  if (variables.count("create-decryption-tables")) {
    if (!has_key) {
      std::cerr << "Key needed for table creation" << std::endl;
      return -1;
    }
    if (!has_decryption_table_file) {
      std::cerr << "Missing decryption table file" << std::endl;
      return -1;
    }

    WhiteBox::ExternalEncoding* input = nullptr;
    WhiteBox::ExternalEncoding* output = nullptr;
    if (has_input_encoding)
      input = &input_encoding;
    if (has_output_encoding)
      output = &output_encoding;

    create_decryption_tables(decryption_table_output, key, create_code, input, output);
  }

  if (variables.count("encrypt")) {
    if (block_cipher_mode != WhiteBox::BlockCipherMode::ECB && !has_iv) {
      std::cerr << "IV needed for CBC/CTR modes" << std::endl;
      return -1;
    }
    if (!has_table) {
      std::cerr << "White box data needed for encryption/decryption"
                << std::endl;
      return -1;
    }

    if (!has_input_file && !has_output_file)
      encrypt(whitebox_table, iv, std::cin, std::cout, block_cipher_mode,
              padding_mode);
    else if (!has_input_file)
      encrypt(whitebox_table, iv, std::cin, output_file, block_cipher_mode,
              padding_mode);
    else if (!has_output_file)
      encrypt(whitebox_table, iv, input_file, std::cout, block_cipher_mode,
              padding_mode);
    else
      encrypt(whitebox_table, iv, input_file, output_file, block_cipher_mode,
              padding_mode);
  }

  if (variables.count("decrypt")) {
    if (block_cipher_mode != WhiteBox::BlockCipherMode::ECB && !has_iv) {
      std::cerr << "IV needed for CBC/CTR modes" << std::endl;
      return -1;
    }
    if (!has_table) {
      std::cerr << "White box data needed for encryption/decryption"
                << std::endl;
      return -1;
    }
    if (!has_input_file && !has_output_file)
      decrypt(whitebox_table, iv, std::cin, std::cout, block_cipher_mode,
              padding_mode);
    else if (!has_input_file)
      decrypt(whitebox_table, iv, std::cin, output_file, block_cipher_mode,
              padding_mode);
    else if (!has_output_file)
      decrypt(whitebox_table, iv, input_file, std::cout, block_cipher_mode,
              padding_mode);
    else
      decrypt(whitebox_table, iv, input_file, output_file, block_cipher_mode,
              padding_mode);
  }

  if (variables.count("encrypt-state")) {
      if (!has_table) {
          std::cerr << "White box data needed for encryption/decryption"
                    << std::endl;
          return -1;
      }

      WhiteBox::State input_state;

      if (!WhiteBox::parse_aes_state(input_state, variables["encrypt-state"].as<std::string>())) {
          std::cerr << "Could not parse state" << std::endl;
          return -1;
      }

      WhiteBox::State result = WhiteBox::interpret_white_box(whitebox_table, input_state, false);
      for (auto byte : result) {
          std::cout << std::hex << static_cast<int>(byte);
      }
      std::cout << std::endl;
  }

  return 0;
}

void encrypt(WhiteBox::WhiteBoxData &data, const WhiteBox::State &iv,
             std::istream &istream, std::ostream &ostream,
             WhiteBox::BlockCipherMode mode, WhiteBox::PaddingMode padding) {
             CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme;

  switch(padding) {
    case WhiteBox::PaddingMode::ZEROS:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING;
      break;
    case WhiteBox::PaddingMode::PKCS:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING;
      break;
    case WhiteBox::PaddingMode::ONE_AND_ZEROS:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING;
      break;
    case WhiteBox::PaddingMode::NONE:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme ::NO_PADDING;
      break;
    default:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING;
  }

  switch(mode) {
    case WhiteBox::BlockCipherMode::ECB:
      WhiteBox::encrypt_ecb_mode(istream, ostream, &data, padding_scheme);
      break;
    case WhiteBox::BlockCipherMode::CTR:
      WhiteBox::encrypt_ctr_mode(istream, ostream, &data, iv, padding_scheme);
      break;
    case WhiteBox::BlockCipherMode::CBC:
      WhiteBox::encrypt_cbc_mode(istream, ostream, &data, iv, padding_scheme);
      break;
    default:
      ;
  }
}

void decrypt(WhiteBox::WhiteBoxData &data, const WhiteBox::State &iv,
             std::istream &istream, std::ostream &ostream,
             WhiteBox::BlockCipherMode mode, WhiteBox::PaddingMode padding) {
             CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme;

  switch(padding) {
    case WhiteBox::PaddingMode::ZEROS:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING;
      break;
    case WhiteBox::PaddingMode::PKCS:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING;
      break;
    case WhiteBox::PaddingMode::ONE_AND_ZEROS:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING;
      break;
    case WhiteBox::PaddingMode::NONE:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme ::NO_PADDING;
      break;
    default:
      padding_scheme = CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING;
  }

  switch(mode) {
    case WhiteBox::BlockCipherMode::ECB:
      WhiteBox::decrypt_ecb_mode(istream, ostream, &data, padding_scheme);
      break;
    case WhiteBox::BlockCipherMode::CTR:
      WhiteBox::decrypt_ctr_mode(istream, ostream, &data, iv, padding_scheme);
      break;
    case WhiteBox::BlockCipherMode::CBC:
      WhiteBox::decrypt_cbc_mode(istream, ostream, &data, iv, padding_scheme);
      break;
    default:
      ;
  }
}

void create_decryption_tables(std::ofstream &ofstream, WhiteBox::State key, bool code,
                              WhiteBox::ExternalEncoding* input_encoding, WhiteBox::ExternalEncoding* output_encoding) {
  auto gen = std::make_unique<WhiteBox::WhiteBoxTableGenerator>(key, true, true);
  std::unique_ptr<WhiteBox::WhiteBoxData> data(gen->getDecryptionTable());
  if (input_encoding != nullptr)
    input_encoding->applyToWhiteBox(data.get(), true);
  if (output_encoding != nullptr)
    output_encoding->applyToWhiteBox(data.get(), false);

  if (!code) {
    boost::archive::text_oarchive ar(ofstream);
    ar << *data;
  } else {
    data->serializeToCStruct(ofstream);
  }
}

void create_encryption_tables(std::ofstream &ofstream, WhiteBox::State key, bool code,
                              WhiteBox::ExternalEncoding* input_encoding, WhiteBox::ExternalEncoding* output_encoding) {
  auto gen = std::make_unique<WhiteBox::WhiteBoxTableGenerator>(key, true, true);
  std::unique_ptr<WhiteBox::WhiteBoxData> data(gen->getEncryptionTable());
  if (input_encoding != nullptr)
    input_encoding->applyToWhiteBox(data.get(), true);
  if (output_encoding != nullptr)
    output_encoding->applyToWhiteBox(data.get(), false);

  if (!code) {
    boost::archive::text_oarchive ar(ofstream);
    ar << *data;
  } else {
    data->serializeToCStruct(ofstream);
  }
}
