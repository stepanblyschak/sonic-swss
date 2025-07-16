#include "dashhaorch.h"

#include "orch.h"
#include "sai.h"
#include "saiextensions.h"
#include "dashorch.h"
#include "crmorch.h"
#include "saihelper.h"
#include "table.h"
#include "taskworker.h" 
#include "pbutils.h"

#include "chrono"

using namespace std;
using namespace swss;

extern sai_dash_ha_api_t*   sai_dash_ha_api;
extern sai_dash_eni_api_t*  sai_dash_eni_api;
extern sai_object_id_t      gSwitchId;
extern sai_switch_api_t*    sai_switch_api;

static const map<sai_ha_set_event_t, string> sai_ha_set_event_type_name =
{
    { SAI_HA_SET_EVENT_DP_CHANNEL_UP, "up" },
    { SAI_HA_SET_EVENT_DP_CHANNEL_DOWN, "down" }
};

static const map<sai_dash_ha_role_t, string> sai_ha_role_name = {
    { SAI_DASH_HA_ROLE_DEAD, "dead" },
    { SAI_DASH_HA_ROLE_ACTIVE, "active" },
    { SAI_DASH_HA_ROLE_STANDBY, "standby" },
    { SAI_DASH_HA_ROLE_STANDALONE, "standalone" },
    { SAI_DASH_HA_ROLE_SWITCHING_TO_ACTIVE, "switching_to_active" },
};

static const map<sai_dash_ha_state_t, string> sai_ha_state_name = {
    { SAI_DASH_HA_STATE_DEAD, "dead" },
    { SAI_DASH_HA_STATE_CONNECTING, "connecting" },
    { SAI_DASH_HA_STATE_CONNECTED, "connected" },
    { SAI_DASH_HA_STATE_INITIALIZING_TO_ACTIVE, "initializing_to_active" },
    { SAI_DASH_HA_STATE_INITIALIZING_TO_STANDBY, "initializing_to_standby" },
    { SAI_DASH_HA_STATE_PENDING_STANDALONE_ACTIVATION, "pending_standalone_activation" },
    { SAI_DASH_HA_STATE_PENDING_ACTIVE_ACTIVATION, "pending_active_activation" },
    { SAI_DASH_HA_STATE_PENDING_STANDBY_ACTIVATION, "pending_standby_activation" },
    { SAI_DASH_HA_STATE_STANDALONE, "standalone" },
    { SAI_DASH_HA_STATE_ACTIVE, "active" },
    { SAI_DASH_HA_STATE_STANDBY, "standby" },
    { SAI_DASH_HA_STATE_DESTROYING, "destroying" },
    { SAI_DASH_HA_STATE_SWITCHING_TO_STANDALONE, "switching_to_standalone" },
};

static const map<sai_ha_scope_event_t, string> sai_ha_scope_event_type_name =
{
    { SAI_HA_SCOPE_EVENT_STATE_CHANGED, "state_changed" },
    { SAI_HA_SCOPE_EVENT_FLOW_RECONCILE_NEEDED, "flow_reconcile_needed" },
    { SAI_HA_SCOPE_EVENT_SPLIT_BRAIN_DETECTED, "split_brain_detected" }
};

DashHaOrch::DashHaOrch(DBConnector *db, const vector<string> &tables, DashOrch *dash_orch, DBConnector *app_state_db, ZmqServer *zmqServer) :
    ZmqOrch(db, tables, zmqServer),
    m_dash_orch(dash_orch)
{
    SWSS_LOG_ENTER();

    dash_ha_set_result_table_ = make_unique<Table>(app_state_db, APP_DASH_HA_SET_TABLE_NAME);
    dash_ha_scope_result_table_ = make_unique<Table>(app_state_db, APP_DASH_HA_SCOPE_TABLE_NAME);

    m_dpuStateDbConnector = make_unique<DBConnector>("DPU_STATE_DB", 0, true);

    m_dpuStateDbHaSetTable = make_unique<Table>(m_dpuStateDbConnector.get(), STATE_DASH_HA_SET_STATE_TABLE_NAME);
    m_dpuStateDbHaScopeTable = make_unique<Table>(m_dpuStateDbConnector.get(), STATE_DASH_HA_SCOPE_STATE_TABLE_NAME);

    DBConnector *notificationsDb = new DBConnector("ASIC_DB", 0);
    m_haSetNotificationConsumer = new NotificationConsumer(notificationsDb, "NOTIFICATIONS");
    auto haSetNotificatier = new Notifier(m_haSetNotificationConsumer, this, "HA_SET_NOTIFICATIONS");

    m_haScopeNotificationConsumer = new NotificationConsumer(notificationsDb, "NOTIFICATIONS");
    auto haScopeNotificatier = new Notifier(m_haScopeNotificationConsumer, this, "HA_SCOPE_NOTIFICATIONS");

    Orch::addExecutor(haSetNotificatier);
    Orch::addExecutor(haScopeNotificatier);

    register_ha_set_notifier();
    register_ha_scope_notifier();
}

bool DashHaOrch::register_ha_set_notifier()
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    sai_status_t status;
    sai_attr_capability_t capability;

    status = sai_query_attribute_capability(gSwitchId, SAI_OBJECT_TYPE_SWITCH,
                                            SAI_SWITCH_ATTR_HA_SET_EVENT_NOTIFY,
                                            &capability);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Unable to query the HA Set event notification capability");
        return false;
    }

    if (!capability.set_implemented)
    {
        SWSS_LOG_INFO("HA Set event notification not supported");
        return false;
    }

    attr.id = SAI_SWITCH_ATTR_HA_SET_EVENT_NOTIFY;
    attr.value.ptr = (void *)on_ha_set_event;

    status = sai_switch_api->set_switch_attribute(gSwitchId, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to register HA Set event notification");
        return false;
    }

    return true;
}

bool DashHaOrch::register_ha_scope_notifier()
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    sai_status_t status;
    sai_attr_capability_t capability;

    status = sai_query_attribute_capability(gSwitchId, SAI_OBJECT_TYPE_SWITCH,
                                            SAI_SWITCH_ATTR_HA_SCOPE_EVENT_NOTIFY,
                                            &capability);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Unable to query the HA Scope event notification capability");
        return false;
    }

    if (!capability.set_implemented)
    {
        SWSS_LOG_INFO("HA Scope event notification not supported");
        return false;
    }

    attr.id = SAI_SWITCH_ATTR_HA_SCOPE_EVENT_NOTIFY;
    attr.value.ptr = (void *)on_ha_scope_event;

    status = sai_switch_api->set_switch_attribute(gSwitchId, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to register HA Scope event notification");
        return false;
    }

    return true;
}

std::string DashHaOrch::getHaSetObjectKey(const sai_object_id_t ha_set_oid)
{
    SWSS_LOG_ENTER();

    for (auto ha_set_entry : m_ha_set_entries)
    {
        if (ha_set_entry.second.ha_set_id == ha_set_oid)
        {
            return ha_set_entry.first;
        }
    }

    return "";
}

std::string DashHaOrch::getHaScopeObjectKey(const sai_object_id_t ha_scope_oid)
{
    SWSS_LOG_ENTER();

    for (auto ha_scope_entry : m_ha_scope_entries)
    {
        if (ha_scope_entry.second.ha_scope_id == ha_scope_oid)
        {
            return ha_scope_entry.first;
        }
    }

    return "";
}

bool DashHaOrch::addHaSetEntry(const std::string &key, const dash::ha_set::HaSet &entry)
{
    SWSS_LOG_ENTER();

    auto it = m_ha_set_entries.find(key);

    if (it != m_ha_set_entries.end())
    {
        SWSS_LOG_WARN("HA Set entry already exists for %s", key.c_str());
        return true;
    }

    uint32_t attr_count = 8;
    sai_attribute_t ha_set_attr_list[8]={};
    sai_status_t status;
    sai_object_id_t sai_ha_set_oid = 0UL;

    sai_ip_address_t sai_local_ip;
    sai_ip_address_t sai_peer_ip;

    if (!to_sai(entry.local_ip(), sai_local_ip))
    {
        return false;
    }

    if (!to_sai(entry.peer_ip(), sai_peer_ip))
    {
        return false;
    }

    ha_set_attr_list[0].id = SAI_HA_SET_ATTR_LOCAL_IP;
    ha_set_attr_list[0].value.ipaddr = sai_local_ip;

    ha_set_attr_list[1].id = SAI_HA_SET_ATTR_PEER_IP;
    ha_set_attr_list[1].value.ipaddr = sai_peer_ip;

    ha_set_attr_list[2].id = SAI_HA_SET_ATTR_CP_DATA_CHANNEL_PORT;
    ha_set_attr_list[2].value.u16 = static_cast<sai_uint16_t>(entry.cp_data_channel_port());
    
    ha_set_attr_list[3].id = SAI_HA_SET_ATTR_DP_CHANNEL_DST_PORT;
    ha_set_attr_list[3].value.u16 = static_cast<sai_uint16_t>(entry.dp_channel_dst_port());

    ha_set_attr_list[4].id = SAI_HA_SET_ATTR_DP_CHANNEL_MIN_SRC_PORT;
    ha_set_attr_list[4].value.u16 = static_cast<sai_uint16_t>(entry.dp_channel_src_port_min());

    ha_set_attr_list[5].id = SAI_HA_SET_ATTR_DP_CHANNEL_MAX_SRC_PORT;
    ha_set_attr_list[5].value.u16 = static_cast<sai_uint16_t>(entry.dp_channel_src_port_max());

    ha_set_attr_list[6].id = SAI_HA_SET_ATTR_DP_CHANNEL_PROBE_INTERVAL_MS;
    ha_set_attr_list[6].value.u32 = entry.dp_channel_probe_interval_ms();

    ha_set_attr_list[7].id = SAI_HA_SET_ATTR_DP_CHANNEL_PROBE_FAIL_THRESHOLD;
    ha_set_attr_list[7].value.u32 = entry.dp_channel_probe_fail_threshold();

    status = sai_dash_ha_api->create_ha_set(&sai_ha_set_oid,
                                                gSwitchId,
                                                attr_count,
                                                ha_set_attr_list);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create HA Set object in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiCreateStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    m_ha_set_entries[key] = HaSetEntry {sai_ha_set_oid, entry};
    SWSS_LOG_NOTICE("Created HA Set object for %s", key.c_str());

    return true;
}

bool DashHaOrch::removeHaSetEntry(const std::string &key)
{
    SWSS_LOG_ENTER();

    auto it = m_ha_set_entries.find(key);

    if (it == m_ha_set_entries.end())
    {
        SWSS_LOG_WARN("HA Set entry does not exist for %s", key.c_str());
        return true;
    }

    sai_status_t status = sai_dash_ha_api->remove_ha_set(it->second.ha_set_id);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove HA Set object in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiRemoveStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    m_ha_set_entries.erase(it);
    SWSS_LOG_NOTICE("Removed HA Set object for %s", key.c_str());

    return true;
}

void DashHaOrch::doTaskHaSetTable(ConsumerBase &consumer)
{
    SWSS_LOG_ENTER();

    uint32_t result;

    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple tuple = it->second;
        const auto& key = kfvKey(tuple);
        const auto& op = kfvOp(tuple);
        result = DASH_RESULT_SUCCESS;

        if (op == SET_COMMAND)
        {
            dash::ha_set::HaSet entry;

            if (!parsePbMessage(kfvFieldsValues(tuple), entry))
            {
                SWSS_LOG_WARN("Requires protobuf at HaSet :%s", key.c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            if (addHaSetEntry(key, entry))
            {
                it = consumer.m_toSync.erase(it);
            }
            else
            {
                result = DASH_RESULT_FAILURE;
                it++;
            }
            writeResultToDB(dash_ha_set_result_table_, key, result);

        }
        else if (op == DEL_COMMAND)
        {
            if(removeHaSetEntry(key))
            {
                it = consumer.m_toSync.erase(it);
                removeResultFromDB(dash_ha_set_result_table_, key);
            }
            else
            {
                it++;
            }
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation %s", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

bool DashHaOrch::addHaScopeEntry(const std::string &key, const dash::ha_scope::HaScope &entry)
{
    SWSS_LOG_ENTER();

    auto ha_scope_it = m_ha_scope_entries.find(key);
    if (ha_scope_it != m_ha_scope_entries.end())
    {
        bool success = true;
        bool repeated_message = true;

        if (ha_scope_it->second.metadata.ha_role() != entry.ha_role())
        {
            success = success && setHaScopeHaRole(key, entry);
            repeated_message = false;
        }

        if (entry.flow_reconcile_requested() == true)
        {
            success = success && setHaScopeFlowReconcileRequest(key);
            repeated_message = false;
        }

        if (entry.activate_role_requested() == true)
        {
            success = success && setHaScopeActivateRoleRequest(key);
            repeated_message = false;
        }

        if (repeated_message)
        {
            SWSS_LOG_WARN("HA Scope entry already exists for %s", key.c_str());
        }
        else
        {
            SWSS_LOG_NOTICE("HA Scope entry updated for %s", key.c_str());
        }

        return success;
    }

    auto ha_set_it = m_ha_set_entries.find(key);
    if (ha_set_it == m_ha_set_entries.end())
    {
        SWSS_LOG_ERROR("HA Set entry does not exist for %s", key.c_str());
        return false;
    }
    sai_object_id_t ha_set_oid = ha_set_it->second.ha_set_id;

    const uint32_t attr_count = 2;
    sai_attribute_t ha_scope_attrs[attr_count]={};
    sai_status_t status;
    sai_object_id_t sai_ha_scope_oid = 0UL;

    ha_scope_attrs[0].id = SAI_HA_SCOPE_ATTR_HA_SET_ID;
    ha_scope_attrs[0].value.oid = ha_set_oid;

    // TODO: add ha_role to attribute value enum
    ha_scope_attrs[1].id = SAI_HA_SCOPE_ATTR_DASH_HA_ROLE;
    ha_scope_attrs[1].value.u16 = to_sai(entry.ha_role());

    status = sai_dash_ha_api->create_ha_scope(&sai_ha_scope_oid,
                                         gSwitchId,
                                         attr_count,
                                         ha_scope_attrs);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create HA Scope object in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiCreateStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    m_ha_scope_entries[key] = HaScopeEntry {sai_ha_scope_oid, entry, getNowTime()};
    SWSS_LOG_NOTICE("Created HA Scope object for %s", key.c_str());

    // set HA Scope ID to ENI
    if (ha_set_it->second.metadata.scope() == dash::types::HaScope::SCOPE_ENI)
    {
        auto eni_entry = m_dash_orch->getEni(key);
        if (eni_entry == nullptr)
        {
            SWSS_LOG_ERROR("ENI entry does not exist for %s", key.c_str());
            return false;
        }

        return setEniHaScopeId(eni_entry->eni_id, sai_ha_scope_oid);

    } else if (ha_set_it->second.metadata.scope() == dash::types::HaScope::SCOPE_DPU)
    {
        auto eni_table = m_dash_orch->getEniTable();
        auto it = eni_table->begin();
        bool success = true;
        while (it != eni_table->end())
        {
            if (!setEniHaScopeId(it->second.eni_id, sai_ha_scope_oid))
            {
                SWSS_LOG_ERROR("Failed to set HA Scope ID for ENI %s", it->first.c_str());
                success = false;
            }
            it++;
        }

        if (!success)
        {
            return false;
        }
    }
    else
    {
        SWSS_LOG_ERROR("Invalid HA Scope type %s: %s", ha_set_it->first.c_str(), dash::types::HaScope_Name(ha_set_it->second.metadata.scope()).c_str());
        return false;
    }

    return true;
}

bool DashHaOrch::setHaScopeHaRole(const std::string &key, const dash::ha_scope::HaScope &entry)
{
    SWSS_LOG_ENTER();

    sai_object_id_t ha_scope_id = m_ha_scope_entries[key].ha_scope_id;

    sai_attribute_t ha_scope_attr;
    ha_scope_attr.id = SAI_HA_SCOPE_ATTR_DASH_HA_ROLE;
    ha_scope_attr.value.u32 = to_sai(entry.ha_role());

    sai_status_t status = sai_dash_ha_api->set_ha_scope_attribute(ha_scope_id,
                                                                &ha_scope_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to set HA Scope role in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiSetStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    SWSS_LOG_NOTICE("Set HA Scope role for %s to %s", key.c_str(), (dash::types::HaRole_Name(entry.ha_role())).c_str());

    return true;
}

bool DashHaOrch::setHaScopeFlowReconcileRequest(const std::string &key)
{
    SWSS_LOG_ENTER();

    sai_object_id_t ha_scope_id = m_ha_scope_entries[key].ha_scope_id;

    sai_attribute_t ha_scope_attr;
    ha_scope_attr.id = SAI_HA_SCOPE_ATTR_FLOW_RECONCILE_REQUESTED;
    ha_scope_attr.value.booldata = true;

    sai_status_t status = sai_dash_ha_api->set_ha_scope_attribute(ha_scope_id,
                                                                &ha_scope_attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to set HA Scope flow reconcile request in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiSetStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    SWSS_LOG_NOTICE("Set HA Scope flow reconcile request for %s", key.c_str());

    return true;
}

bool DashHaOrch::setHaScopeActivateRoleRequest(const std::string &key)
{
    SWSS_LOG_ENTER();

    sai_object_id_t ha_scope_id = m_ha_scope_entries[key].ha_scope_id;

    sai_attribute_t ha_scope_attr;
    ha_scope_attr.id = SAI_HA_SCOPE_ATTR_ACTIVATE_ROLE;
    ha_scope_attr.value.booldata = true;

    sai_status_t status = sai_dash_ha_api->set_ha_scope_attribute(ha_scope_id,
                                                                &ha_scope_attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to set HA Scope activate role request in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiSetStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    SWSS_LOG_NOTICE("Set HA Scope activate role request for %s", key.c_str());

    return true;
}

bool DashHaOrch::setEniHaScopeId(const sai_object_id_t eni_id, const sai_object_id_t ha_scope_id)
{
    SWSS_LOG_ENTER();

    sai_attribute_t eni_attr;
    eni_attr.id = SAI_ENI_ATTR_HA_SCOPE_ID;
    eni_attr.value.oid = ha_scope_id;
    sai_status_t status = sai_dash_eni_api->set_eni_attribute(eni_id, &eni_attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to set HA Scope ID for ENI %s", std::to_string(eni_id).c_str());
        task_process_status handle_status = handleSaiSetStatus((sai_api_t) SAI_API_DASH_ENI, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    return true;
}

bool DashHaOrch::removeHaScopeEntry(const std::string &key)
{
    SWSS_LOG_ENTER();

    auto it = m_ha_scope_entries.find(key);

    if (it == m_ha_scope_entries.end())
    {
        SWSS_LOG_WARN("HA Scope entry does not exist for %s", key.c_str());
        return true;
    }

    sai_status_t status = sai_dash_ha_api->remove_ha_scope(it->second.ha_scope_id);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove HA Scope object in SAI for %s", key.c_str());
        task_process_status handle_status = handleSaiRemoveStatus((sai_api_t) SAI_API_DASH_HA, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    m_ha_scope_entries.erase(it);
    SWSS_LOG_NOTICE("Removed HA Scope object for %s", key.c_str());

    return true;
}

void DashHaOrch::doTaskHaScopeTable(ConsumerBase &consumer)
{
    SWSS_LOG_ENTER();

    uint32_t result;

    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple tuple = it->second;
        const auto& key = kfvKey(tuple);
        const auto& op = kfvOp(tuple);
        result = DASH_RESULT_SUCCESS;

        if (op == SET_COMMAND)
        {
            dash::ha_scope::HaScope entry;

            if (!parsePbMessage(kfvFieldsValues(tuple), entry))
            {
                SWSS_LOG_WARN("Requires protobuf at HaScope :%s", key.c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            if (addHaScopeEntry(key, entry))
            {
                it = consumer.m_toSync.erase(it);
            }
            else
            {
                result = DASH_RESULT_FAILURE;
                it++;
            }
            writeResultToDB(dash_ha_scope_result_table_, key, result);
        }
        else if (op == DEL_COMMAND)
        {
            if(removeHaScopeEntry(key))
            {
                it = consumer.m_toSync.erase(it);
                removeResultFromDB(dash_ha_scope_result_table_, key);
            }
            else
            {
                it++;
            }
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation %s", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void DashHaOrch::doTask(ConsumerBase &consumer)
{
    SWSS_LOG_ENTER();

    if (consumer.getTableName() == APP_DASH_HA_SET_TABLE_NAME)
    {
        doTaskHaSetTable(consumer);
    }
    else if (consumer.getTableName() == APP_DASH_HA_SCOPE_TABLE_NAME)
    {
        doTaskHaScopeTable(consumer);
    } else
    {
        SWSS_LOG_ERROR("Unknown table: %s", consumer.getTableName().c_str());
    }
}

void DashHaOrch::doTask(NotificationConsumer &consumer)
{
    SWSS_LOG_ENTER();

    std::deque<KeyOpFieldsValuesTuple> events;
    consumer.pops(events);

    for (auto &event : events)
    {
        std::string op = kfvOp(event);
        std::string data = kfvKey(event);
        std::vector<swss::FieldValueTuple> values = kfvFieldsValues(event);

        if (op == "ha_set_event")
        {
            std::time_t now_time = getNowTime();

            uint32_t count;
            sai_ha_set_event_data_t *ha_set_event = nullptr;

            sai_deserialize_ha_set_event_ntf(data, count, &ha_set_event);

            for (uint32_t i = 0; i < count; i++)
            {
                sai_object_id_t ha_set_id = ha_set_event[i].ha_set_id;
                sai_ha_set_event_t event_type = ha_set_event[i].event_type;

                SWSS_LOG_INFO("Get HA Set event notification id:%" PRIx64 " event: Data plane channel goes %s", ha_set_id, sai_ha_set_event_type_name.at(event_type).c_str());

                auto key = getHaSetObjectKey(ha_set_id);
                if (key.empty())
                {
                    SWSS_LOG_ERROR("HA Set object not found for ID: %" PRIx64, ha_set_id);
                    continue;
                }
                std::vector<FieldValueTuple> fvs = {
                    {"last_updated_time", to_string(now_time)},
                    {"dp_channel_is_alive", sai_ha_set_event_type_name.at(event_type)}
                };
                m_dpuStateDbHaSetTable->set(key, fvs);
            }
            sai_deserialize_free_ha_set_event_ntf(count, ha_set_event);
        }

        if (op == "ha_scope_event")
        {
            std::time_t now_time = getNowTime();

            uint32_t count;
            sai_ha_scope_event_data_t *ha_scope_event = nullptr;

            sai_deserialize_ha_scope_event_ntf(data, count, &ha_scope_event);

            for (uint32_t i = 0; i < count; i++)
            {
                sai_ha_scope_event_t event_type = ha_scope_event[i].event_type;
                sai_object_id_t ha_scope_id = ha_scope_event[i].ha_scope_id;

                SWSS_LOG_INFO("Get HA Scope event notification id:%" PRIx64 " event: %s", ha_scope_id, sai_ha_scope_event_type_name.at(event_type).c_str());

                auto key = getHaScopeObjectKey(ha_scope_id);
                if (key.empty())
                {
                    SWSS_LOG_ERROR("HA Scope object not found for ID: %" PRIx64, ha_scope_id);
                    continue;
                }

                std::vector<FieldValueTuple> fvs = {
                    {"last_updated_time", to_string(now_time)}
                };

                auto ha_role = to_pb(ha_scope_event[i].ha_role);
                std::time_t role_start_time = now_time;

                if (m_ha_scope_entries[key].metadata.ha_role() != ha_role)
                {
                    m_ha_scope_entries[key].metadata.set_ha_role(ha_role);
                    m_ha_scope_entries[key].last_role_start_time = now_time;
                    SWSS_LOG_NOTICE("HA Scope role changed for %s to %s", key.c_str(), dash::types::HaRole_Name(ha_role).c_str());
                } else
                {
                    role_start_time = m_ha_scope_entries[key].last_role_start_time;
                }

                fvs.push_back({"ha_role", sai_ha_role_name.at(ha_scope_event[i].ha_role)});
                fvs.push_back({"ha_role_start_time ", to_string(role_start_time)});

                switch (event_type)
                {
                    case SAI_HA_SCOPE_EVENT_FLOW_RECONCILE_NEEDED:
                        fvs.push_back({"flow_reconcile_pending", "true"});
                        break;
                    case SAI_HA_SCOPE_EVENT_SPLIT_BRAIN_DETECTED:
                        fvs.push_back({"brainsplit_recover_pending", "true"});
                        break;
                    case SAI_HA_SCOPE_EVENT_STATE_CHANGED:
                        if (in(ha_scope_event[i].ha_state, {SAI_DASH_HA_STATE_PENDING_STANDALONE_ACTIVATION,
                                                            SAI_DASH_HA_STATE_PENDING_ACTIVE_ACTIVATION,
                                                            SAI_DASH_HA_STATE_PENDING_STANDBY_ACTIVATION}))
                        {
                            fvs.push_back({"activate_role_pending", "true"});
                            SWSS_LOG_NOTICE("DPU is pending on role activation for %s", key.c_str());
                        }

                        fvs.push_back({"ha_state", sai_ha_state_name.at(ha_scope_event[i].ha_state)});
                        break;
                    default:
                        SWSS_LOG_ERROR("Unknown HA Scope event type %d for %s", event_type, key.c_str());
                }

                m_dpuStateDbHaScopeTable->set(key, fvs);

            }
            sai_deserialize_free_ha_scope_event_ntf(count, ha_scope_event);
        }
    }
}
