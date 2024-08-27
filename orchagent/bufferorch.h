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

class SaiBulkContext
{
public:
    using sai_object_set_attribute_fn = sai_status_t (*)(
        _In_ const sai_object_id_t object_id,
        _In_ const sai_attribute_t *attr);


    SaiBulkContext(sai_api_t api, sai_object_type_t objectType, sai_object_set_attribute_fn setFunc, sai_bulk_object_set_attribute_fn setBulkFunc);

    sai_status_t set(sai_object_id_t oid, sai_attribute_t attr);

    void flush();

private:
    sai_api_t                        m_api;
    sai_object_meta_key_t            m_meta;
    sai_object_type_t                m_objectType;
    sai_bulk_object_set_attribute_fn m_setBulkFunc;
    sai_object_set_attribute_fn      m_setFunc;

    std::vector<sai_object_id_t> m_oids;
    std::vector<sai_status_t>    m_statuses;
    std::vector<sai_attribute_t> m_attrs;

    // SaiAttrWrapper has ownership of heap allocated data referenced by m_attrs.
    std::vector<SaiAttrWrapper>       m_attrContainers;
};

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

    SaiBulkContext m_portApi;
    SaiBulkContext m_ingressPriorityGroupApi;
    SaiBulkContext m_queueApi;
};
#endif /* SWSS_BUFFORCH_H */
