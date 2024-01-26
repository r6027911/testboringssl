
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <map>
#include <chrono>
#include <thread>

#include "boringssl/ssl/ja3/ssl_ja3.h"

#include "boringssl/ssl/internal.h"


#include "transport_common.h"
#include <regex>
#include <json/json.h>


#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */


static bssl::UniquePtr<BIO> session_out;
static bssl::UniquePtr<SSL_SESSION> resume_session;
static SSL *ssl;



static std::string DoConnection(SSL_CTX* ctx, std::map<std::string, std::string> args_map, bool (*cb)(SSL* ssl, int sock)) {
    int sock = -1;
    
    if (!Connect(&sock, args_map["-connect"])) {
        return false;
    }   
     

    bssl::UniquePtr<BIO> bio(BIO_new_socket(sock, BIO_CLOSE));
    ssl = SSL_new(ctx);

    ja3::SSL_ja3& ja3 = ja3::SSL_ja3::getInstance();
    ja3.configureExtensions(ssl);

    SSL_set_bio(ssl, bio.get(), bio.get());
    bio.release();

    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int ssl_err = SSL_get_error(ssl, ret);
        PrintSSLError(stderr, "Error while connecting", ssl_err, ret);
        return false;
    }

    fprintf(stderr, "Connected.\n");
    bssl::UniquePtr<BIO> bio_stderr(BIO_new_fp(stderr, BIO_NOCLOSE));
    PrintConnectionInfo(bio_stderr.get(), ssl);
    fprintf(stderr, "\n");

    std::string request = "GET " + args_map["-path"] + " HTTP/1.1\r\n"
        "Host: " + args_map["-connect"] + "\r\n"
        "Connection: close\r\n"
        "\r\n";

    int ed_size = request.size();
    int ssl_ret = SSL_write(ssl, request.data(), ed_size);

    char buffer[4096];
    std::string response = "";
    int bytesRead;
    while ((bytesRead = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        response += std::string(buffer, bytesRead);
    }

    cb(ssl, sock);
    
    return  response;
}


bool Client(std::vector<std::string>& args) {
    if (!InitSocketLibrary()) {
        return false;
    }

    std::map<std::string, std::string> args_map;

    if (args.size() <= 1) {
        args.push_back(std::string("https://tls.peet.ws/api/tls"));
    }

    std::string url = args[1];
    std::smatch match;
    std::regex urlRegex("^(https?://)?(www\\.[^/]+|[^/]+)(/.*)?$");
    if (std::regex_match(url, match, urlRegex)) {

        args_map["-connect"] = match[2];
        args_map["-path"] = match[3].str().empty() ? "/" : match[3].str();
    }
    else {
        std::cout << "URL does not match expected format" << std::endl;
        return false;
    }
        
    
    std::string fingerPrintFile = std::filesystem::current_path().string() + "/fingerprint_test.txt";
    std::ifstream fStream(fingerPrintFile, std::ios::binary);
    std::string line;
    ja3::SSL_ja3 &ja3 = ja3::SSL_ja3::getInstance();
    

    while (std::getline(fStream, line))
    {
        std::cout << std::endl << std::endl;
        std::cout << "Processing fingerprint:" << std::endl << line << std::endl;
       
        ja3.InitForString(line);
     
        bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

        std::cout << "Validate ciphers: ";
        std::vector<uint16_t>badCiphers = ja3.ssl_ja3_validate_ciphers();
        if (!badCiphers.empty()) {
            std::cout << RED << "ERROR" << RESET << std::endl;
            std::cout << "Not valid ciphers:" << std::endl;
            for (auto id : badCiphers) {
                std::cout << id << " ";
            }
            std::cout << std::endl << "SKIPPED" << std::endl;
            continue;
        }
        std::cout << GREEN << "OK" << RESET << std::endl;
        std::cout << "Validate extensions: ";
        std::vector<uint16_t>badExt = ja3.ssl_ja3_validate_extensions();
        if (!badExt.empty()) {
            std::cout << RED << "ERROR" <<RESET << std::endl;
            std::cout << "Not valid extensions:" << std::endl;
            for (auto id : badExt) {
                std::cout << id << " ";
            }
            std::cout << std::endl << "SKIPPED" << std::endl;
            continue;
        }
        std::cout << GREEN << "OK" << RESET << std::endl;
        std::cout << "Processing network request to https://tls.peet.ws/api/tls" << std::endl;
        
        std::string response = DoConnection(ctx.get(), args_map, &TransferData);

        std::cout << "Write server response to file" << std::endl;
        ja3.Log(response);
        std::cout << "Validating server response ja3 : " << std::endl;;

        Json::Reader reader;
        Json::Value root;

        std::regex rgx("\\n(\\{[\\S\\s]*)");
        std::smatch matches;

        if (std::regex_search(response, matches, rgx)) {            
            bool parseSuccess = reader.parse(matches[1], root, false);
            Json::StyledWriter styledWriter;
            if (parseSuccess) {
                const Json::Value resultValue = root["tls"]["ja3"];
                std::string serverJa3Str = resultValue.asString();
                std::cout << "serverJa3Str: " << serverJa3Str << std::endl;
                std::cout << "configJa3Str: " << &line[2] << std::endl;
                if (serverJa3Str.compare(&line[2]) == 0) {
                    std::cout << GREEN << "OK, Strings matched" << RESET << std::endl;
                }
                else {
                    std::cout << RED << "EROR, Strings not matched" << RESET << std::endl;
                    std::cout << "Our ja3 string    : " << &line[2] << std::endl;
                    std::cout << "Server ja3 string : " << serverJa3Str << std::endl;
                }
            }
            else {
                std::cout << RED << "EROR, Parsing server response" << RESET << std::endl;
            }       
        
        }
        else {
            std::cout << RED << "EROR, Parsing server response" << RESET << std::endl;
        }
    }  

    return true;
}


int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }

    if (!Client(args)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}
