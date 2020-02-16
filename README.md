# AES Whitebox encryption

This project implements the AES White Box encryption scheme as
outlined in 2002 by Chow et al.

It requires the following dependencies:

* Boost (`program_options` and `serialization`). 
  Can be acquired on Debian-based Linux distributions via `apt`:
  `sudo apt-get install libboost1.67-all-dev`

* NTL (used for linear algebra on finite fields)
  Can be acquired on Debian-based Linux distributions via `apt`:
  `sudo apt-get install libntl-dev`

* Crypto++ (used mainly for the platform-independent cryptographic random number
  generator, also for modes of operation)
  Can be acquired on Debian-based Linux distributions via `apt`:
  `sudo apt-get install libcrypto++-dev`

All dependencies can be quickly acquired on Ubuntu using
`sudo apt-get install libboost1.67-all-dev libntl-dev libcrypto++-dev`

### Whitebox cryptography implementations

This is an implementation of a white-box cryptography scheme, in particular the
one from 2002, by Chow et al. For more info on white-box cryptography, see http://www.whiteboxcrypto.com/

This implementation supports:
* Generating a table that can be used by the program to encrypt and decrypt data streams
* Generating a C++ header that can be used with the C++ source file in the /gen
folder to automatically create a program that implements a WBC cipher


The implementation is written in C++.
The build system is CMake. It is recommended to do out-of-source
builds with CMake.

The actual program can then be accessed via a command line interface.
The following options are available:

* `--help`: Displays options
* `--create encryption tables` Create a table for encryption
  in a given file, use later with --whitebox-table
* `--create encryption tables` Create a table for decryption
  in a given file, use later with --whitebox-table
* `--create-c-file` Create a C++ struct containing the whitebox,
  for embedding in other programs.
* `--key arg` The key to use for creating the tables
* `--whitebox-table arg` This is for encrypting/decrypting
  given an existing whitebox table
* `--set mode ARG` Set block cipher mode, either CBC/CTR/ECB
* `--iv arg` IV for CBC/CTR mode
* `--set-padding ARG` Set padding mode, default PKCS/NONE for CTR
* `--encrypt` Use table to encrypt
* `--decrypt` Use table to decrypt
* `--input-file ARG` input file to use, default stdin
* `--output-file ARG` output file to use, default stdout
* `--encrypt-state ARG` encrypt/decrypt hex AES state on commandline using whitebox table
* `--create-external-encoding` arg Create external encodings in given file
* `--apply-input-encoding` arg Apply input encoding to white box
* `--apply-output-encoding` arg Apply output encoding to white box


It supports encryption and decryption with ECB, CBC and CTR modes.

## License

This project uses the ISC license
