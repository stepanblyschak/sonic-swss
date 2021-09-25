#ifndef SWSS_ACLORCH_H
#define SWSS_ACLORCH_H

#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <tuple>
#include <map>
#include <condition_variable>

#include "orch.h"
#include "switchorch.h"
#include "portsorch.h"
#include "mirrororch.h"
#include "dtelorch.h"
#include "observer.h"
#include "flex_counter_manager.h"

#include "acltable.h"

#define RULE_PRIORITY           "PRIORITY"
#define MATCH_IN_PORTS          "IN_PORTS"
#define MATCH_OUT_PORTS         "OUT_PORTS"
#define MATCH_SRC_IP            "SRC_IP"
#define MATCH_DST_IP            "DST_IP"
#define MATCH_SRC_IPV6          "SRC_IPV6"
#define MATCH_DST_IPV6          "DST_IPV6"
#define MATCH_L4_SRC_PORT       "L4_SRC_PORT"
#define MATCH_L4_DST_PORT       "L4_DST_PORT"
#define MATCH_ETHER_TYPE        "ETHER_TYPE"
#define MATCH_IP_PROTOCOL       "IP_PROTOCOL"
#define MATCH_NEXT_HEADER       "NEXT_HEADER"
#define MATCH_VLAN_ID           "VLAN_ID"
#define MATCH_TCP_FLAGS         "TCP_FLAGS"
#define MATCH_IP_TYPE           "IP_TYPE"
#define MATCH_DSCP              "DSCP"
#define MATCH_L4_SRC_PORT_RANGE "L4_SRC_PORT_RANGE"
#define MATCH_L4_DST_PORT_RANGE "L4_DST_PORT_RANGE"
#define MATCH_TC                "TC"
#define MATCH_ICMP_TYPE         "ICMP_TYPE"
#define MATCH_ICMP_CODE         "ICMP_CODE"
#define MATCH_ICMPV6_TYPE       "ICMPV6_TYPE"
#define MATCH_ICMPV6_CODE       "ICMPV6_CODE"
#define MATCH_TUNNEL_VNI        "TUNNEL_VNI"
#define MATCH_INNER_ETHER_TYPE  "INNER_ETHER_TYPE"
#define MATCH_INNER_IP_PROTOCOL "INNER_IP_PROTOCOL"
#define MATCH_INNER_L4_SRC_PORT "INNER_L4_SRC_PORT"
#define MATCH_INNER_L4_DST_PORT "INNER_L4_DST_PORT"

#define ACTION_PACKET_ACTION                "PACKET_ACTION"
#define ACTION_REDIRECT_ACTION              "REDIRECT_ACTION"
#define ACTION_DO_NOT_NAT_ACTION            "DO_NOT_NAT_ACTION"
#define ACTION_MIRROR_ACTION                "MIRROR_ACTION"
#define ACTION_MIRROR_INGRESS_ACTION        "MIRROR_INGRESS_ACTION"
#define ACTION_MIRROR_EGRESS_ACTION         "MIRROR_EGRESS_ACTION"
#define ACTION_DTEL_FLOW_OP                 "FLOW_OP"
#define ACTION_DTEL_INT_SESSION             "INT_SESSION"
#define ACTION_DTEL_DROP_REPORT_ENABLE      "DROP_REPORT_ENABLE"
#define ACTION_DTEL_TAIL_DROP_REPORT_ENABLE "TAIL_DROP_REPORT_ENABLE"
#define ACTION_DTEL_FLOW_SAMPLE_PERCENT     "FLOW_SAMPLE_PERCENT"
#define ACTION_DTEL_REPORT_ALL_PACKETS      "REPORT_ALL_PACKETS"

#define PACKET_ACTION_FORWARD     "FORWARD"
#define PACKET_ACTION_DROP        "DROP"
#define PACKET_ACTION_REDIRECT    "REDIRECT"
#define PACKET_ACTION_DO_NOT_NAT  "DO_NOT_NAT"

#define DTEL_FLOW_OP_NOP        "NOP"
#define DTEL_FLOW_OP_POSTCARD   "POSTCARD"
#define DTEL_FLOW_OP_INT        "INT"
#define DTEL_FLOW_OP_IOAM       "IOAM"

#define DTEL_ENABLED             "TRUE"
#define DTEL_DISABLED            "FALSE"

#define IP_TYPE_ANY             "ANY"
#define IP_TYPE_IP              "IP"
#define IP_TYPE_NON_IP          "NON_IP"
#define IP_TYPE_IPv4ANY         "IPV4ANY"
#define IP_TYPE_NON_IPv4        "NON_IPv4"
#define IP_TYPE_IPv6ANY         "IPV6ANY"
#define IP_TYPE_NON_IPv6        "NON_IPv6"
#define IP_TYPE_ARP             "ARP"
#define IP_TYPE_ARP_REQUEST     "ARP_REQUEST"
#define IP_TYPE_ARP_REPLY       "ARP_REPLY"

#define MLNX_MAX_RANGES_COUNT   16
#define INGRESS_TABLE_DROP      "IngressTableDrop"
#define RULE_OPER_ADD           0
#define RULE_OPER_DELETE        1

#define ACL_COUNTER_FLEX_COUNTER_GROUP "ACL_STAT_COUNTER"

typedef map<string, sai_acl_entry_attr_t> acl_rule_attr_lookup_t;
typedef map<string, sai_acl_ip_type_t> acl_ip_type_lookup_t;
typedef map<string, sai_acl_dtel_flow_op_t> acl_dtel_flow_op_type_lookup_t;
typedef map<string, sai_packet_action_t> acl_packet_action_lookup_t;
typedef tuple<sai_acl_range_type_t, int, int> acl_range_properties_t;
typedef map<acl_stage_type_t, set<sai_acl_action_type_t>> acl_capabilities_t;
typedef map<sai_acl_action_type_t, set<int32_t>> acl_action_enum_values_capabilities_t;

class AclOrch;

class AclRange
{
public:
    static AclRange *create(sai_acl_range_type_t type, int min, int max);
    static bool remove(sai_acl_range_type_t type, int min, int max);
    static bool remove(sai_object_id_t *oids, int oidsCnt);
    sai_object_id_t getOid()
    {
        return m_oid;
    }

private:
    AclRange(sai_acl_range_type_t type, sai_object_id_t oid, int min, int max);
    bool remove();
    sai_object_id_t m_oid;
    int m_refCnt;
    int m_min;
    int m_max;
    sai_acl_range_type_t m_type;
    static map<acl_range_properties_t, AclRange*> m_ranges;
};

class AclRule
{
public:
    AclRule(AclOrch *pAclOrch, string rule, string table, bool createCounter = true);
    virtual bool validateAddPriority(string attr_name, string attr_value);
    virtual bool validateAddMatch(string attr_name, string attr_value);
    virtual bool validateAddAction(string attr_name, string attr_value);
    virtual bool validate() = 0;
    bool processIpType(string type, sai_uint32_t &ip_type);
    inline static void setRulePriorities(sai_uint32_t min, sai_uint32_t max)
    {
        m_minPriority = min;
        m_maxPriority = max;
    }

    virtual bool create();
    virtual bool remove();
    virtual bool update(AclRule& updatedRule);
    virtual void onUpdate(SubjectType, void *) = 0;
    virtual void updateInPorts();

    virtual bool enableCounter();
    virtual bool disableCounter();

    sai_object_id_t getOid() const
    {
        return m_ruleOid;
    }

    string getId() const
    {
        return m_id;
    }

    string getTableId() const
    {
        return m_tableId;
    }

    sai_object_id_t getCounterOid() const
    {
        return m_counterOid;
    }

    bool hasCounter() const
    {
        return getCounterOid() != SAI_NULL_OBJECT_ID;
    }

    vector<sai_object_id_t> getInPorts()
    {
        return m_inPorts;
    }

    static shared_ptr<AclRule> makeShared(AclOrch *acl, MirrorOrch *mirror, DTelOrch *dtel, const string& rule, const string& table, const KeyOpFieldsValuesTuple&);
    virtual ~AclRule() {}

protected:
    virtual bool createCounter();
    virtual bool removeCounter();
    virtual bool createRanges();
    virtual bool removeRanges();
    virtual bool removeRule();

    bool updatePriority(AclRule& updatedRule);
    bool updateMatches(AclRule& updatedRule);
    bool updateActions(AclRule& updatedRule);
    bool updateMatchRanges(AclRule& updatedRule);
    bool updateCounter(AclRule& updatedRule);

    bool isActionSupported(sai_acl_entry_attr_t) const;

    static sai_uint32_t m_minPriority;
    static sai_uint32_t m_maxPriority;
    AclOrch *m_pAclOrch;
    string m_id;
    string m_tableId;
    sai_object_id_t m_tableOid;
    sai_object_id_t m_ruleOid;
    sai_object_id_t m_counterOid;
    uint32_t m_priority;
    map <sai_acl_entry_attr_t, sai_attribute_value_t> m_matches;
    map <sai_acl_entry_attr_t, sai_attribute_value_t> m_actions;

    vector<sai_object_id_t> m_range_objects;
    map<sai_acl_range_type_t, pair<uint32_t, uint32_t>> m_ranges;

    vector<sai_object_id_t> m_inPorts;
    vector<sai_object_id_t> m_outPorts;

private:
    bool m_enableCounter;
};

class AclRulePacket: public AclRule
{
public:
    AclRulePacket(AclOrch *m_pAclOrch, string rule, string table, bool createCounter = true);

    bool create() override;
    bool remove() override;

    bool validateAddAction(string attr_name, string attr_value);
    bool validate();
    void onUpdate(SubjectType, void *) override;

protected:
    sai_object_id_t getRedirectObjectId(const string& redirect_param);
    void decreaseNextHopRefCount();

private:
    string m_redirect_target_next_hop;
    string m_redirect_target_next_hop_group;
};

class AclRulePfcwd: public AclRulePacket
{
public:
    AclRulePfcwd(AclOrch *m_pAclOrch, string rule, string table, bool createCounter = false);
};

class AclRuleMux: public AclRulePacket
{
public:
    AclRuleMux(AclOrch *m_pAclOrch, string rule, string table, bool createCounter = false);
};

class AclRuleMirror: public AclRule
{
public:
    AclRuleMirror(AclOrch *m_pAclOrch, MirrorOrch *m_pMirrorOrch, string rule, string table);
    bool validateAddAction(string attr_name, string attr_value);
    bool validate() override;
    bool create() override;
    bool remove() override;
    bool update(AclRule& updatedRule) override;
    bool activate();
    bool deactivate();
    void onUpdate(SubjectType, void *) override;

protected:
    bool m_state {false};
    string m_sessionName;
    MirrorOrch *m_pMirrorOrch {nullptr};
};

class AclRuleDTelFlowWatchListEntry: public AclRule
{
public:
    AclRuleDTelFlowWatchListEntry(AclOrch *m_pAclOrch, DTelOrch *m_pDTelOrch, string rule, string table);
    bool validateAddAction(string attr_name, string attr_value);
    bool validate() override;
    bool create() override;
    bool remove() override;
    bool update(AclRule& updatedRule) override;
    void onUpdate(SubjectType, void *) override;

protected:
    DTelOrch *m_pDTelOrch;
    string m_intSessionId;
    bool INT_enabled;
    bool INT_session_valid;
};

class AclRuleDTelDropWatchListEntry: public AclRule
{
public:
    AclRuleDTelDropWatchListEntry(AclOrch *m_pAclOrch, DTelOrch *m_pDTelOrch, string rule, string table);
    bool validateAddAction(string attr_name, string attr_value);
    bool validate() override;
    void onUpdate(SubjectType, void *) override;

protected:
    DTelOrch *m_pDTelOrch;
};

class AclRuleMclag: public AclRulePacket
{
public:
    AclRuleMclag(AclOrch *m_pAclOrch, string rule, string table, bool createCounter = false);
    bool validate() override;
};

class AclTable
{
public:
    AclTable(AclOrch *pAclOrch, string id) noexcept;
    AclTable(AclOrch *pAclOrch) noexcept;

    AclTable() = default;
    ~AclTable() = default;

    sai_object_id_t getOid() { return m_oid; }
    string getId() { return id; }

    void setDescription(const string &value) { description = value; }
    const string& getDescription() const { return description; }

    bool validateAddType(const acl_table_type_t &value);
    bool validateAddStage(const acl_stage_type_t &value);
    bool validateAddPorts(const unordered_set<string> &value);
    bool validate();
    bool create();

    // Bind the ACL table to a port which is already linked
    bool bind(sai_object_id_t portOid);
    // Unbind the ACL table to a port which is already linked
    bool unbind(sai_object_id_t portOid);
    // Bind the ACL table to all ports linked
    bool bind();
    // Unbind the ACL table to all ports linked
    bool unbind();
    // Link the ACL table with a port, for future bind or unbind
    void link(sai_object_id_t portOid);
    // Unlink the ACL table from a port after unbind
    void unlink(sai_object_id_t portOid);
    // Add or overwrite a rule into the ACL table
    bool add(shared_ptr<AclRule> newRule);
    // Remove a rule from the ACL table
    bool remove(string rule_id);
    // Update existing rule and replace with new one.
    bool updateRule(shared_ptr<AclRule> updatedRule);
    // Remove all rules from the ACL table
    bool clear();
    // Update table subject to changes
    void onUpdate(SubjectType, void *);

public:
    string id;
    string description;

    acl_table_type_t type = ACL_TABLE_UNKNOWN;
    acl_stage_type_t stage = ACL_STAGE_INGRESS;

    // Map port oid to group member oid
    std::map<sai_object_id_t, sai_object_id_t> ports;
    // Map rule name to rule data
    map<string, shared_ptr<AclRule>> rules;
    // Set to store the ACL table port alias
    set<string> portSet;
    // Set to store the not configured ACL table port alias
    set<string> pendingPortSet;

private:
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;
    AclOrch *m_pAclOrch = nullptr;
};

class AclOrch : public Orch, public Observer
{
public:
    AclOrch(vector<TableConnector>& connectors,
            SwitchOrch              *m_switchOrch,
            PortsOrch               *portOrch,
            MirrorOrch              *mirrorOrch,
            NeighOrch               *neighOrch,
            RouteOrch               *routeOrch,
            DTelOrch                *m_dTelOrch = NULL);
    ~AclOrch();
    void update(SubjectType, void *);

    sai_object_id_t getTableById(string table_id);
    const AclTable* getTableByOid(sai_object_id_t oid) const;

    static swss::Table& getCountersTable()
    {
        return m_countersTable;
    }

    // FIXME: Add getters for them? I'd better to add a common directory of orch objects and use it everywhere
    MirrorOrch *m_mirrorOrch;
    NeighOrch *m_neighOrch;
    RouteOrch *m_routeOrch;
    DTelOrch *m_dTelOrch;

    bool addAclTable(AclTable &aclTable);
    bool removeAclTable(string table_id);
    bool updateAclTable(AclTable &currentTable, AclTable &newTable);
    bool updateAclTable(string table_id, AclTable &table);
    bool addAclRule(shared_ptr<AclRule> aclRule, string table_id);
    bool removeAclRule(string table_id, string rule_id);
    bool updateAclRule(shared_ptr<AclRule> updatedRule);
    bool updateAclRule(string table_id, string rule_id, string attr_name, void *data, bool oper);
    bool updateAclRule(string table_id, string rule_id, bool enableCounter);
    AclRule* getAclRule(string table_id, string rule_id);

    bool isCombinedMirrorV6Table();
    bool isAclMirrorTableSupported(acl_table_type_t type) const;
    bool isAclActionSupported(acl_stage_type_t stage, sai_acl_action_type_t action) const;
    bool isAclActionEnumValueSupported(sai_acl_action_type_t action, sai_acl_action_parameter_t param) const;

    bool m_isCombinedMirrorV6Table = true;
    map<acl_table_type_t, bool> m_mirrorTableCapabilities;

    static sai_acl_action_type_t getAclActionFromAclEntry(sai_acl_entry_attr_t attr);

    // Get the OID for the ACL bind point for a given port
    static bool getAclBindPortId(Port& port, sai_object_id_t& port_id);

    using Orch::doTask;  // Allow access to the basic doTask
    map<sai_object_id_t, AclTable>  getAclTables()
    {
        return m_AclTables;
    }

private:
    SwitchOrch *m_switchOrch;
    void doTask(Consumer &consumer);
    void doAclTableTask(Consumer &consumer);
    void doAclRuleTask(Consumer &consumer);
    void init(vector<TableConnector>& connectors, PortsOrch *portOrch, MirrorOrch *mirrorOrch, NeighOrch *neighOrch, RouteOrch *routeOrch);

    void queryMirrorTableCapability();
    void queryAclActionCapability();
    void initDefaultAclActionCapabilities(acl_stage_type_t);
    void putAclActionCapabilityInDB(acl_stage_type_t);

    template<typename AclActionAttrLookupT>
    void queryAclActionAttrEnumValues(const string& action_name,
                                      const acl_rule_attr_lookup_t& ruleAttrLookupMap,
                                      const AclActionAttrLookupT lookupMap);

    static void collectCountersThread(AclOrch *pAclOrch);

    bool createBindAclTable(AclTable &aclTable, sai_object_id_t &table_oid);
    sai_status_t bindAclTable(AclTable &aclTable, bool bind = true);
    sai_status_t deleteUnbindAclTable(sai_object_id_t table_oid);

    bool isAclTableTypeUpdated(acl_table_type_t table_type, AclTable &aclTable);
    bool processAclTableType(string type, acl_table_type_t &table_type);
    bool isAclTableStageUpdated(acl_stage_type_t acl_stage, AclTable &aclTable);
    bool processAclTableStage(string stage, acl_stage_type_t &acl_stage);
    bool processAclTablePorts(string portList, AclTable &aclTable);
    bool validateAclTable(AclTable &aclTable);
    bool updateAclTablePorts(AclTable &newTable, AclTable &curTable);
    void getAddDeletePorts(AclTable    &newT,
                           AclTable    &curT,
                           set<string> &addSet,
                           set<string> &delSet);
    sai_status_t createDTelWatchListTables();
    sai_status_t deleteDTelWatchListTables();

    void registerFlexCounter(const AclRule& rule);
    void deregisterFlexCounter(const AclRule& rule);
    string generateAclRuleIdentifierInCountersDb(const AclRule& rule) const;

    map<sai_object_id_t, AclTable> m_AclTables;
    // TODO: Move all ACL tables into one map: name -> instance
    map<string, AclTable> m_ctrlAclTables;

    static DBConnector m_db;
    static Table m_countersTable;

    map<acl_stage_type_t, string> m_mirrorTableId;
    map<acl_stage_type_t, string> m_mirrorV6TableId;

    acl_capabilities_t m_aclCapabilities;
    acl_action_enum_values_capabilities_t m_aclEnumActionCapabilities;
    Table m_acl_counter_rule_map;
    FlexCounterManager m_flex_counter_manager;
};

#endif /* SWSS_ACLORCH_H */
