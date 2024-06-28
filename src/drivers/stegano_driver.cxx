#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <numeric>

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
#include "../../include/drivers/stegano_driver.hpp"

using namespace CryptoPP;
using namespace cv;

typedef std::vector<int> int_arr;
typedef std::vector<unsigned char> bytes;

bytes SteganoDriver::hide_and_encrypt(
    cv::Mat cover,
    cv::Mat data,
    CryptoPP::SecByteBlock key,
    int num_lsb)
{
    std::cout << "Encrypting..." << std::endl;
    int dim_len = 2 * 8;
    int type_len = 1 * 8;
    int prefix_len = (2 * dim_len) + type_len;

    cv::Mat flat_cover = cover.reshape(0, cover.total());

    int data_rows = data.rows;
    int data_cols = data.cols;
    cv::Mat flat_data = data.reshape(0, data.total());

    if (cover.total() < (data.total() * 8) + prefix_len)
    {
        throw std::runtime_error("Error: secret image too large for the cover image.");
    }
    if (cover.type() != data.type() || cover.type() > 255)
    {
        throw std::runtime_error("Error: secret image different type than cover image.");
    }

    int_arr permutation = create_permutation(key, (flat_cover.size[0] / 8));

    cv::Vec3b hidden_pixel, cover_pixel, hidden_data;

    int img_type = cover.type();
    int hidden_rows = data.rows;
    int hidden_cols = data.cols;
    if (hidden_rows > 65535 || hidden_cols > 65535)
    {
        throw std::runtime_error("Error: secret image too large.");
    }

    for (int i = 0; i < type_len; i++)
    {
        cover_pixel = flat_cover.at<cv::Vec3b>(Point(0, permutation[i] * 8));
        if ((img_type & 1) != 0)
        {
            cover_pixel[0] |= 1;
        }
        else
        {
            cover_pixel[0] &= ~1;
        }
        img_type = img_type >> 1;
        flat_cover.at<cv::Vec3b>(Point(0, permutation[i] * 8)) = cover_pixel;
    }
    for (int i = type_len; i < type_len + dim_len; i++)
    {
        cover_pixel = flat_cover.at<cv::Vec3b>(Point(0, permutation[i] * 8));
        if ((hidden_rows & 1) != 0)
        {
            cover_pixel[0] |= 1;
        }
        else
        {
            cover_pixel[0] &= ~1;
        }
        hidden_rows = hidden_rows >> 1;
        flat_cover.at<cv::Vec3b>(Point(0, permutation[i] * 8)) = cover_pixel;
    }
    for (int i = type_len + dim_len; i < prefix_len; i++)
    {
        cover_pixel = flat_cover.at<cv::Vec3b>(Point(0, permutation[i] * 8));
        if ((hidden_cols & 1) != 0)
        {
            cover_pixel[0] |= 1;
        }
        else
        {
            cover_pixel[0] &= ~1;
        }
        hidden_cols = hidden_cols >> 1;
        flat_cover.at<cv::Vec3b>(Point(0, permutation[i] * 8)) = cover_pixel;
    }

    int cover_index;
    int hidden_lsb;

    for (int i = prefix_len; i < flat_data.size[0] + prefix_len; i++)
    {
        hidden_pixel = flat_data.at<cv::Vec3b>(Point(0, i - prefix_len));
        cover_index = permutation[i] * 8;
        for (int j = 0; j < 8; j++)
        {
            cover_pixel = flat_cover.at<cv::Vec3b>(Point(0, cover_index));
            for (int l = 0; l < 3; l++)
            {
                if ((hidden_pixel[l] & 1) != 0)
                {
                    cover_pixel[l] |= 1;
                }
                else
                {
                    cover_pixel[l] &= ~1;
                }
                hidden_pixel[l] = hidden_pixel[l] >> 1;
            }
            flat_cover.at<cv::Vec3b>(Point(0, cover_index)) = cover_pixel;
            cover_index += 1;
        }
    }

    bytes stegano_data;

    if (flat_cover.isContinuous())
    {
        stegano_data.assign(flat_cover.data, flat_cover.data + flat_cover.total() * flat_cover.elemSize());
    }
    else
    {
        throw std::runtime_error("Cover image's matrix is not continuous");
    }
    // std::cout << "Finished Encrypting" << std::endl;

    cv::Mat transmitted_image = flat_cover.reshape(0, cover.rows);
    try
    {
        cv::imwrite("../meta_images/transmitted_image.jpg", transmitted_image);
    }
    catch (cv::Exception &ex)
    {
        const char *msg = ex.what();
        std::cout << msg << std::endl;
    }

    return stegano_data;
}

cv::Mat SteganoDriver::decrypt_and_extract(
    bytes data,
    CryptoPP::SecByteBlock key,
    int num_lsb)
{
    std::cout << "Decrypting..." << std::endl;
    int dim_len = 2 * 8;
    int type_len = 1 * 8;
    int prefix_len = (2 * dim_len) + type_len;

    cv::Mat cover_image(data.size() / (3 * sizeof(unsigned char)), 1, 16);

    if (!data.empty())
    {
        std::memcpy(cover_image.data, data.data(), data.size() * sizeof(unsigned char));
    }
    int_arr inverse_permutation = create_permutation(key, (cover_image.size[0] / 8));

    int cover_index;
    cv::Vec3b hidden_pixel, cover_pixel;
    int img_type = 0, hidden_rows = 0, hidden_cols = 0;
    for (int i = type_len - 1; i >= 0; i--)
    {
        cover_index = inverse_permutation[i] * 8;
        cover_pixel = cover_image.at<cv::Vec3b>(Point(0, cover_index));
        if ((cover_pixel[0] & 1) != 0) // lsb = 1
        {
            img_type |= 1;
        }
        if (i > 0)
        {
            img_type = img_type << 1;
        }
    }
    for (int i = type_len + dim_len - 1; i >= type_len; i--)
    {
        cover_index = inverse_permutation[i] * 8;
        cover_pixel = cover_image.at<cv::Vec3b>(Point(0, cover_index));
        if ((cover_pixel[0] & 1) != 0) // lsb = 1
        {
            hidden_rows |= 1;
        }
        if (i > type_len)
        {
            hidden_rows = hidden_rows << 1;
        }
    }
    for (int i = prefix_len - 1; i >= type_len + dim_len; i--)
    {
        cover_index = inverse_permutation[i] * 8;
        cover_pixel = cover_image.at<cv::Vec3b>(Point(0, cover_index));
        if ((cover_pixel[0] & 1) != 0) // lsb = 1
        {
            hidden_cols |= 1;
        }
        if (i > type_len + dim_len)
        {
            hidden_cols = hidden_cols << 1;
        }
    }
    int hidden_size = hidden_cols * hidden_rows;

    cv::Mat hidden_image(hidden_rows * hidden_cols, 1, 16);
    int cover_index_base;
    for (int i = prefix_len; i < prefix_len + hidden_size; i++)
    {
        cover_index_base = inverse_permutation[i] * 8;
        hidden_pixel = {0, 0, 0};
        for (int j = 7; j >= 0; j--)
        {
            cover_index = cover_index_base + j;
            cover_pixel = cover_image.at<cv::Vec3b>(Point(0, cover_index));
            for (int l = 0; l < 3; l++)
            {
                if ((cover_pixel[l] & 1) != 0) // lsb = 1
                {
                    hidden_pixel[l] |= 1;
                }
                if (j > 0)
                {
                    hidden_pixel[l] = hidden_pixel[l] << 1;
                }
            }
        }
        hidden_image.at<cv::Vec3b>(Point(0, i - prefix_len)) = hidden_pixel;
    }
    // std::cout << "hidden cols: " << hidden_cols << std::endl;
    // std::cout << "hidden rows: " << hidden_cols << std::endl;
    // std::cout << "hidden image size " << hidden_image.size() << std::endl;
    hidden_image = hidden_image.reshape(0, hidden_cols);
    // std::cout << "Finished Decrypting" << std::endl;
    return hidden_image;
}

// in -> key (bytes); n (num of bits in lsb chunk);
// out -> permutation and inverted permutation as int arrays
int_arr SteganoDriver::create_permutation(CryptoPP::SecByteBlock key, int data_length)
{
    /*
    ----if we use bytes as key, use this, if we use SecByteBlock use code below----
            -- i think we should definitely use SecByteBlock for key - Gabriel
    unsigned long i = 0;
    for (unsigned char digit: key) {
        result = 10 * result + digit;
    }
    std::default_random_engine generator(i.ConvertToLong());
    */
    CryptoPP::Integer i = byteblock_to_integer(key);
    // if (!i.IsConvertableToLong())
    // {
    //     throw std::runtime_error("key isn't convertable to long");
    // }
    std::default_random_engine generator(i.ConvertToLong());
    std::vector<int> idx(data_length);
    std::iota(idx.begin(), idx.end(), 0);
    std::shuffle(idx.begin(), idx.end(), generator);

    std::vector<int> inv_idx(data_length);
    for (int i = 0; i < data_length; i++)
    {
        inv_idx[idx[i]] = i;
    }
    // return std::make_pair(idx, inv_idx); // if inverse permutation needed
    return idx;
}
