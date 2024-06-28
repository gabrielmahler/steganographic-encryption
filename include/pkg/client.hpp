#pragma once

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/drivers/stegano_driver.hpp"

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include "../../include-shared/messages.hpp"


class Client
{
public:
  Client(std::shared_ptr<NetworkDriver> network_driver, std::shared_ptr<CryptoDriver> crypto_driver, std::shared_ptr<SteganoDriver> stegano_driver);
  void run(std::string cmd);
  void prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value);
  void HandleKeyExchange(std::string command);
  
private:
  std::shared_ptr<NetworkDriver> network_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<SteganoDriver> stegano_driver;
  SecByteBlock AES_key;
  SecByteBlock HMAC_key;
  void ReceiveThread();
  void SendThread();
  DHParams_Message DH_params;
  bool DH_switched;
  SecByteBlock DH_current_private_value;
  SecByteBlock DH_current_public_value;
  SecByteBlock DH_last_other_public_value;
  std::mutex mtx;
};