// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_config.h"

#include "base/files/file_util.h"
#include "net/cert/cert_verifier.h"

namespace net {

SSL_ja3::SSL_ja3() : need_check(true), version_(0), was_init_(false),
	file_log_(base::FilePath(FILE_PATH_LITERAL("custome_log.txt")), 
		base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_APPEND)
{}

void SSL_ja3::LogMessage(std::string str){
  std::ostringstream stream_;
  stream_ << str << std::endl;
  std::string str_done(stream_.str());
  file_log_.Write(0, str_done.c_str(), str_done.length());
}


void SSL_ja3::InitFromFile() {
  if (was_init_ == false) {
    base::FilePath sett_file = base::FilePath(FILE_PATH_LITERAL("finger.txt"));
    std::string finger_data;
    if (base::ReadFileToString(sett_file, &finger_data) == true) {
      // TODO add code, init params from code
      InitForString(finger_data);
	  //InitForTesting();
      was_init_ = true;
    }
  }
}

void SSL_ja3::InitForString(std::string str) {
  
  std::vector<std::string> first = split_string(str, ',');
  
  need_check = first[0] == "1";
  
  version_ = std::stoi(first[1]);

  std::vector<std::string> ciphers = split_string(first[2], '-');
  cipher_suites_ = convert_str_to_unit16(ciphers);
  
  std::vector<std::string> exts = split_string(first[3], '-');
  custom_ext_ = convert_str_to_unit16(exts);

  std::vector<std::string> groups_lists = split_string(first[4], '-');
  custom_supported_group_list_ = convert_str_to_unit16(groups_lists);

  std::vector<std::string> points_lists = split_string(first[5], '-');
  custom_points_ = convert_str_to_unit8(points_lists);
}

std::vector<std::string> SSL_ja3::split_string(std::string str, char delim) {
  std::stringstream line;
  line.str(str);

  std::string segment;
  std::vector<std::string> seglist;

  while (std::getline(line, segment, delim)) {
    seglist.push_back(segment);
  }

  return seglist;
}

std::vector<uint16_t> SSL_ja3::convert_str_to_unit16(
    std::vector<std::string>& strs) {
  std::vector<uint16_t> result;
  for (std::string code : strs) {
    uint16_t cph = std::stoi(code);
    result.push_back(cph);
  }
  return result;
}

std::vector<uint8_t> SSL_ja3::convert_str_to_unit8(
    std::vector<std::string>& strs) {
  std::vector<uint8_t> result;
  for (std::string code : strs) {
    uint8_t cph = std::stoi(code);
    result.push_back(cph);
  }
  return result;
}

void SSL_ja3::InitForTesting() {
  version_ = 771;
  // 4865,  4866,  4867,  49196, 49195, 49188, 49187, 49162, 49161,
  // 52393, 49200, 49199, 49192, 49191, 49172, 49171, 52392, 157,
  // 156,   61,    60,    53,    47,    49160, 49170, 10
  cipher_suites_.push_back(4865);
  cipher_suites_.push_back(4866);
  cipher_suites_.push_back(4867);
  cipher_suites_.push_back(49196);
  cipher_suites_.push_back(49195);
  cipher_suites_.push_back(49188);
  cipher_suites_.push_back(49188);
  cipher_suites_.push_back(49187);
  cipher_suites_.push_back(49162);
  cipher_suites_.push_back(49161);
  cipher_suites_.push_back(52393);
  cipher_suites_.push_back(49200);
  cipher_suites_.push_back(49199);
  cipher_suites_.push_back(49192);
  cipher_suites_.push_back(49191);
  cipher_suites_.push_back(49172);
  cipher_suites_.push_back(49171);
  cipher_suites_.push_back(52392);
  cipher_suites_.push_back(157);
  cipher_suites_.push_back(156);
  cipher_suites_.push_back(61);
  cipher_suites_.push_back(60);
  cipher_suites_.push_back(53);
  cipher_suites_.push_back(47);
  cipher_suites_.push_back(49160);
  cipher_suites_.push_back(49170);
  cipher_suites_.push_back(10);

  // 65281, 0, 23, 13, 5, 18, 16, 11, 51, 45, 43, 10, 21
  custom_ext_.push_back(65281);
  custom_ext_.push_back(0);
  custom_ext_.push_back(23);
  custom_ext_.push_back(13);
  custom_ext_.push_back(5);
  custom_ext_.push_back(18);
  custom_ext_.push_back(16);
  custom_ext_.push_back(11);
  custom_ext_.push_back(51);
  custom_ext_.push_back(45);
  custom_ext_.push_back(43);
  custom_ext_.push_back(10);
  custom_ext_.push_back(21);

  // 29, 23, 24, 25;
  custom_supported_group_list_.push_back(29);
  custom_supported_group_list_.push_back(23);
  custom_supported_group_list_.push_back(24);
  custom_supported_group_list_.push_back(25);
}

const uint16_t kDefaultSSLVersionMin = SSL_PROTOCOL_VERSION_TLS1;

const uint16_t kDefaultSSLVersionMax = SSL_PROTOCOL_VERSION_TLS1_2;

const TLS13Variant kDefaultTLS13Variant = kTLS13VariantDraft23;

SSLConfig::CertAndStatus::CertAndStatus() = default;
SSLConfig::CertAndStatus::CertAndStatus(scoped_refptr<X509Certificate> cert_arg,
                                        CertStatus status)
    : cert(std::move(cert_arg)), cert_status(status) {}
SSLConfig::CertAndStatus::CertAndStatus(const CertAndStatus& other) = default;
SSLConfig::CertAndStatus::~CertAndStatus() = default;

SSLConfig::SSLConfig()
    : version_min(kDefaultSSLVersionMin),
      version_max(kDefaultSSLVersionMax),
      tls13_variant(kDefaultTLS13Variant),
      early_data_enabled(false),
      version_interference_probe(false),
      channel_id_enabled(false),
      false_start_enabled(true),
      require_ecdhe(false),
      disable_cert_verification_network_fetches(false),
      send_client_cert(false),
      renego_allowed_default(false) {}

SSLConfig::SSLConfig(const SSLConfig& other) = default;

SSLConfig::~SSLConfig() = default;

bool SSLConfig::IsAllowedBadCert(X509Certificate* cert,
                                 CertStatus* cert_status) const {
  for (const auto& allowed_bad_cert : allowed_bad_certs) {
    if (cert->EqualsExcludingChain(allowed_bad_cert.cert.get())) {
      if (cert_status)
        *cert_status = allowed_bad_cert.cert_status;
      return true;
    }
  }
  return false;
}

int SSLConfig::GetCertVerifyFlags() const {
  int flags = 0;
  if (disable_cert_verification_network_fetches)
    flags |= CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES;

  return flags;
}

}  // namespace net
