/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "BlacklistSrcFile.h"
#include "Ddosmitigator.h"
#include "polycube/common.h"

using namespace polycube::service;

BlacklistSrcFile::BlacklistSrcFile(Ddosmitigator &parent, const BlacklistSrcFileJsonObject &conf)
    : parent_(parent) {
  logger()->debug("BlacklistSrcFile Constructor. file {0} ", conf.getFile());
  this->file_ = conf.getFile();

}

BlacklistSrcFile::~BlacklistSrcFile() {
  auto srcFileBlacklist =
      parent_.get_percpuhash_table<uint32_t, uint64_t>("srcblacklist");
  logger()->debug("BlacklistSrcFile Destructor. file {0} ", file_);
  try {
    srcFileBlacklist.remove_all();
  } catch (...) {
  }
}

void BlacklistSrcFile::update(const BlacklistSrcFileJsonObject &conf) {
  // This method updates all the object/parameter in BlacklistSrcFile object
  // specified in the conf JsonObject.
  // You can modify this implementation.
  logger()->error("BlacklistSrcFile update. This method should never be called ");
}

std::string BlacklistSrcFile::getFile() {
  logger()->debug("BlacklistSrcFile getFile {0} ", this->file_);

  return this->file_;
}

BlacklistSrcFileJsonObject BlacklistSrcFile::toJsonObject() {
  BlacklistSrcFileJsonObject conf;

  try {
    conf.setFile(getFile());
  } catch (...) {
  }
  logger()->debug("BlacklistSrcFile toJsonObject");

  return conf;
}

std::shared_ptr<spdlog::logger> BlacklistSrcFile::logger() {
  return parent_.logger();
}