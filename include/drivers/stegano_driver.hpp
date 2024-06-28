#pragma once

#include <iostream>
#include <stdexcept>
#include <string>

#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;
using namespace cv;

typedef std::vector<int> int_arr;
typedef std::vector<unsigned char> bytes;

class SteganoDriver
{
public:
    bytes hide_and_encrypt(
        cv::Mat cover,
        cv::Mat data,
        CryptoPP::SecByteBlock key,
        int num_lsb = 0);
    cv::Mat decrypt_and_extract(
        bytes data,
        CryptoPP::SecByteBlock key,
        int num_lsb = 0);
    int_arr create_permutation(CryptoPP::SecByteBlock key, int data_length);
};