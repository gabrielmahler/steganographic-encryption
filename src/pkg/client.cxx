#include "../../include/pkg/client.hpp"

#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include-shared/messages.hpp"

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

using namespace cv;

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
// namespace {
// src::severity_logger<logging::trivial::severity_level> lg;
// }

/**
 * Constructor.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver,
               std::shared_ptr<SteganoDriver> stegano_driver)
{
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->stegano_driver = stegano_driver;
  initLogger(logging::trivial::severity_level::trace);
}

void Client::run(std::string cmd)
{
  std::string image_path = samples::findFile("../cover_images/cover2.jpg");
  cv::Mat img = imread(image_path, IMREAD_COLOR);

  if (img.empty())
  {
    std::cout << "Could not read the image: " << image_path << std::endl;
    return;
  }

  std::string hidden_image_path = samples::findFile("../secret_images/hidden1.jpg");
  cv::Mat hidden_img = imread(hidden_image_path, IMREAD_COLOR);

  if (hidden_img.empty())
  {
    std::cout << "Could not read the image: " << hidden_image_path << std::endl;
    return;
  }

  // TESTING
  // AutoSeededRandomPool rng;
  // const size_t dataSize = 4;
  // SecByteBlock key(dataSize);
  // rng.GenerateBlock(key, key.size());

  // std::cout << "Calling driver" << std::endl;
  // std::cout << "  driver encrypt" << std::endl;
  // std::vector<unsigned char> encrypted_bytes = this->stegano_driver->hide_and_encrypt(img, hidden_img, key);
  // std::cout << "  driver decrypt" << std::endl;
  // cv::Mat output = this->stegano_driver->decrypt_and_extract(encrypted_bytes, key);
  // std::cout << "Done" << std::endl;

  // try
  // {
  //   cv::imwrite("../output/test1.jpg", output);
  // }
  // catch (cv::Exception &ex)
  // {
  //   const char *msg = ex.what();
  //   std::cout << msg << std::endl;
  // }

  this->cli_driver->init();
  this->HandleKeyExchange(cmd);
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();

  return;
}

void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value)
{
  // TODO: implement me!
  SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  this->AES_key = this->crypto_driver->AES_generate_key(shared_key);
  this->HMAC_key = this->crypto_driver->HMAC_generate_key(shared_key);
}

void Client::HandleKeyExchange(std::string command)
{
  DHParams_Message dh;
  if (command == "listen")
  {
    std::vector<unsigned char> data;
    try
    {
      data = this->network_driver->read();
    }
    catch (std::runtime_error &_)
    {
      this->cli_driver->print_left("Received EOF; closing connection 1");
      this->network_driver->disconnect();
      return;
    }
    dh.deserialize(data);
  }
  else if (command == "connect")
  {
    dh = this->crypto_driver->DH_generate_params();
    std::vector<unsigned char> dh_data;
    dh.serialize(dh_data);
    network_driver->send(dh_data);
  }
  this->DH_params = dh;
  std::tuple<DH, SecByteBlock, SecByteBlock> init_dh = this->crypto_driver->DH_initialize(dh);
  this->DH_current_private_value = std::get<1>(init_dh);
  std::vector<unsigned char> pub_val_data;
  SecByteBlock pub_val_block = std::get<2>(init_dh);
  this->DH_current_public_value = pub_val_block;
  PublicValue_Message pub_val;
  pub_val.public_value = pub_val_block;
  pub_val.serialize(pub_val_data);
  network_driver->send(pub_val_data);
  std::vector<unsigned char> their_pub_val_data;
  try
  {
    their_pub_val_data = this->network_driver->read();
  }
  catch (std::runtime_error &_)
  {
    this->cli_driver->print_left("Received EOF; closing connection 2");
    this->network_driver->disconnect();
    return;
  }
  PublicValue_Message their_pub_val;
  their_pub_val.deserialize(their_pub_val_data);
  SecByteBlock their_pub_val_block = their_pub_val.public_value;
  this->DH_last_other_public_value = their_pub_val_block;
  DH dh_obj = std::get<0>(init_dh);
  SecByteBlock priv_val = std::get<1>(init_dh);
  this->prepare_keys(dh_obj, priv_val, their_pub_val_block);
  this->DH_switched = true;
}

void Client::ReceiveThread()
{
  while (true)
  {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try
    {
      data = this->network_driver->read();
    }
    catch (std::runtime_error &_)
    {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection 3");
      this->network_driver->disconnect();
      return;
    }
    cv::Mat received_image = this->stegano_driver->decrypt_and_extract(data, this->AES_key);
    this->cli_driver->print_left("Received an encrypted image");
    try
    {
      cv::imwrite("../output/received_image.jpg", received_image);
    }
    catch (cv::Exception &ex)
    {
      const char *msg = ex.what();
      std::cout << msg << std::endl;
    }
    this->cli_driver->print_left("Secret image saved in /outputs as received_image.jpg");
  }
}

void Client::SendThread()
{
  std::string plaintext, token, hidden_image_path, cover_image_path;
  std::vector<std::string> tokens;
  this->cli_driver->print_left("Connection established.");
  while (true)
  {
    std::getline(std::cin, plaintext);
    std::istringstream iss(plaintext);

    if (std::cin.eof())
    {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    while (iss >> token)
    {
      tokens.push_back(token);
    }
    if (tokens.size() != 3)
    {
      this->cli_driver->print_right("invalid input. use: send <hidden-image-path> <cover-image-path>");
      // this->cli_driver->print_right(std::to_string(tokens.size()));
    }
    else
    {
      hidden_image_path = tokens[1];
      cover_image_path = tokens[2];
      cv::Mat hidden_img = imread(hidden_image_path, IMREAD_COLOR);
      if (hidden_img.empty())
      {
        this->cli_driver->print_right("Could not read hidden image");
        std::cout << "Could not read the image: " << hidden_image_path << std::endl;
      }
      else
      {
        cv::Mat cover_img = imread(cover_image_path, IMREAD_COLOR);
        if (cover_img.empty())
        {
          this->cli_driver->print_right("Could not read cover image");
          std::cout << "Could not read the image: " << cover_image_path << std::endl;
        }
        else
        {
          std::vector<unsigned char> encrypted_bytes = this->stegano_driver->hide_and_encrypt(cover_img, hidden_img, this->AES_key);

          // cv::Mat testimg = this->stegano_driver->decrypt_and_extract(encrypted_bytes, this->AES_key);
          // try
          // {
          //   cv::imwrite("../output/test.jpg", testimg);
          // }
          // catch (cv::Exception &ex)
          // {
          //   const char *msg = ex.what();
          //   std::cout << msg << std::endl;
          // }

          this->network_driver->send(encrypted_bytes);
          this->cli_driver->print_left("Image sent!");
        }
      }
    }
    tokens.clear();
  }
}