#pragma once

#include "gearboxutils.h"

#include <string>

void initSaiApi();
void initSaiRedis(const std::string &record_location, const std::string &record_filename);
sai_status_t initSaiPhyApi(swss::gearbox_phy_t *phy);

bool compareAclAction(sai_acl_entry_attr_t id, sai_acl_action_data_t first, sai_acl_action_data_t second);
bool compareAclField(sai_acl_entry_attr_t id, sai_acl_field_data_t first, sai_acl_field_data_t second);
