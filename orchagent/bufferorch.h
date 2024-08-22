#ifndef SWSS_BUFFORCH_H
#define SWSS_BUFFORCH_H

#include <string>
#include <map>
#include <unordered_map>
#include "orch.h"
#include "portsorch.h"
#include "redisapi.h"

#include "saiattr.h"

#define BUFFER_POOL_WATERMARK_STAT_COUNTER_FLEX_COUNTER_GROUP "BUFFER_POOL_WATERMARK_STAT_COUNTER"

const string buffer_size_field_name         = "size";
const string buffer_pool_type_field_name    = "type";
const string buffer_pool_mode_field_name    = "mode";
const string buffer_pool_field_name         = "pool";
const string buffer_pool_mode_dynamic_value = "dynamic";
const string buffer_pool_mode_static_value  = "static";
const string buffer_pool_xoff_field_name    = "xoff";
const string buffer_xon_field_name          = "xon";
const string buffer_xon_offset_field_name   = "xon_offset";
const string buffer_xoff_field_name         = "xoff";
const string buffer_dynamic_th_field_name   = "dynamic_th";
const string buffer_static_th_field_name    = "static_th";
const string buffer_profile_field_name      = "profile";
const string buffer_value_ingress           = "ingress";
const string buffer_value_egress            = "egress";
const string buffer_value_both              = "both";
const string buffer_profile_list_field_name = "profile_list";
const string buffer_headroom_type_field_name= "headroom_type";

class BufferOrch : public Orch
{
public:
    BufferOrch(DBConnector *applDb, DBConnector *confDb, DBConnector *stateDb, vector<string> &tableNames);
    bool isPortReady(const std::string& port_name) const;
    static type_map m_buffer_type_maps;
    void generateBufferPoolWatermarkCounterIdList(void);
    const object_reference_map &getBufferPoolNameOidMap(void);

private:
    typedef task_process_status (BufferOrch::*buffer_table_handler)(KeyOpFieldsValuesTuple &tuple);
    typedef map<string, buffer_table_handler> buffer_table_handler_map;
    typedef pair<string, buffer_table_handler> buffer_handler_pair;

    void doTask() override;
    virtual void doTask(Consumer& consumer);
    void clearBufferPoolWatermarkCounterIdList(const sai_object_id_t object_id);
    void initTableHandlers();
    void initBufferReadyLists(DBConnector *confDb, DBConnector *applDb);
    void initBufferReadyList(Table& table, bool isConfigDb);
    void initVoqBufferReadyList(Table& table, bool isConfigDb);
    void initFlexCounterGroupTable(void);
    void initBufferConstants();
    task_process_status processBufferPool(KeyOpFieldsValuesTuple &tuple);
    task_process_status processBufferProfile(KeyOpFieldsValuesTuple &tuple);
    task_process_status processQueue(KeyOpFieldsValuesTuple &tuple);
    task_process_status processPriorityGroup(KeyOpFieldsValuesTuple &tuple);
    task_process_status processIngressBufferProfileList(KeyOpFieldsValuesTuple &tuple);
    task_process_status processEgressBufferProfileList(KeyOpFieldsValuesTuple &tuple);

    buffer_table_handler_map m_bufferHandlerMap;
    std::unordered_map<std::string, bool> m_ready_list;
    std::unordered_map<std::string, std::vector<std::string>> m_port_ready_list_ref;

    unique_ptr<DBConnector> m_flexCounterDb;
    unique_ptr<ProducerTable> m_flexCounterGroupTable;
    unique_ptr<ProducerTable> m_flexCounterTable;

    Table m_stateBufferMaximumValueTable;

    unique_ptr<DBConnector> m_countersDb;

    bool m_isBufferPoolWatermarkCounterIdListGenerated = false;
    set<string> m_partiallyAppliedQueues;

    // Bulk stuff

    struct
    {
        std::vector<sai_object_id_t> oid;
        std::vector<sai_status_t> statuses;
        std::vector<sai_attribute_t> attr;
    } m_setIngressPriorityGroupBulk;

    struct
    {
        std::vector<sai_object_id_t> oid;
        std::vector<sai_status_t> statuses;
        std::vector<sai_attribute_t> attr;
    } m_setQueueBulk;

    struct
    {
        std::vector<sai_object_id_t> oid;
        std::vector<sai_status_t> statuses;
        std::vector<SaiAttrWrapper> attr;
    } m_setPortAttributeBulk;

    sai_status_t setIngressPriorityGroupAttribute(sai_object_id_t oid, sai_attribute_t attr)
    {
        m_setIngressPriorityGroupBulk.oid.push_back(oid);
        m_setIngressPriorityGroupBulk.statuses.push_back(SAI_STATUS_SUCCESS);
        m_setIngressPriorityGroupBulk.attr.push_back(attr);

        return SAI_STATUS_SUCCESS;
    }

    sai_status_t setQueueAttribute(sai_object_id_t oid, sai_attribute_t attr)
    {
        m_setQueueBulk.oid.push_back(oid);
        m_setQueueBulk.statuses.push_back(SAI_STATUS_SUCCESS);
        m_setQueueBulk.attr.push_back(attr);

        return SAI_STATUS_SUCCESS;
    }

    sai_status_t setPortAttribute(sai_object_id_t oid, sai_attribute_t attr)
    {
        m_setPortAttributeBulk.oid.push_back(oid);
        m_setPortAttributeBulk.statuses.push_back(SAI_STATUS_SUCCESS);
        m_setPortAttributeBulk.attr.emplace_back(SAI_OBJECT_TYPE_PORT, attr);

        return SAI_STATUS_SUCCESS;
    }

    void flushIngressPriorityGroupAttributes();
    void flushQueueAttributes();
    void flushPortAttributes();
};
#endif /* SWSS_BUFFORCH_H */
