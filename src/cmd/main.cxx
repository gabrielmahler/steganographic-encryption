#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/client.hpp"

/*
 * Usage: ./client <listen|connect> [address] [port]
 */
int main(int argc, char *argv[])
{
  //   // Initialize logger
  //   initLogger(logging::trivial::severity_level::trace);

  // Parse args
  if (!(argc == 4))
  {
    std::cout << "Usage: ./client <listen|connect> [address] [port]"
              << std::endl;
    return 1;
  }

  std::string command = argv[1];
  std::string address = argv[2];
  int port = atoi(argv[3]);
  if (command != "listen" && command != "connect")
  {
    std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port]"
              << std::endl;
    return 1;
  }

  // Initialize logger
  initLogger(logging::trivial::severity_level::trace);

  // Connect to network driver.
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  if (command == "listen")
  {
    network_driver->listen(port);
  }
  else if (command == "connect")
  {
    network_driver->connect(address, port);
  }
  else
  {
    throw std::runtime_error("Error: got invalid client command.");
  }
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();
  std::shared_ptr<SteganoDriver> stegano_driver = std::make_shared<SteganoDriver>();
  Client client = Client(network_driver, crypto_driver, stegano_driver);
  client.run(command);
  return 0;
}