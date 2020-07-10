/**
* ddosmitigator API generated from ddosmitigator.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* BlacklistSrcFileJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  BlacklistSrcFileJsonObject : public JsonObjectBase {
public:
  BlacklistSrcFileJsonObject();
  BlacklistSrcFileJsonObject(const nlohmann::json &json);
  ~BlacklistSrcFileJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Absolute path of blacklist file
  /// </summary>
  std::string getFile() const;
  void setFile(std::string value);
  bool fileIsSet() const;
  void unsetFile();

private:
  std::string m_file;
  bool m_fileIsSet;
};

}
}
}
}

