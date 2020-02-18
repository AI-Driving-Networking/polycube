/**
* dynmon API generated from dynmon.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */


#include "MetricsBase.h"
#include "../Dynmon.h"


MetricsBase::MetricsBase(Dynmon &parent)
    : parent_(parent) {}

MetricsBase::~MetricsBase() {}

void MetricsBase::update(const MetricsJsonObject &conf) {

}

MetricsJsonObject MetricsBase::toJsonObject() {
  MetricsJsonObject conf;

  conf.setName(getName());
  conf.setValue(getValue());
  conf.setTimestamp(getTimestamp());

  return conf;
}

std::shared_ptr<spdlog::logger> MetricsBase::logger() {
  return parent_.logger();
}

