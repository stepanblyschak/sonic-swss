#ifndef SWSS_ACLORCH_H
#define SWSS_ACLORCH_H

#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <tuple>
#include <map>

#include "orch.h"
#include "switchorch.h"
#include "portsorch.h"
#include "mirrororch.h"
#include "dtelorch.h"
#include "observer.h"

#include "acltable.h"

// ACL counters update interval in the DB
// Value is in seconds. Should not be less than 5 seconds
// (in worst case update of 1265 counters takes almost 5 sec)
#define COUNTERS_READ_INTERVAL 10

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

#define BIND_POINT_TYPE_PORT "PORT"
#define BIND_POINT_TYPE_PORTCHANNEL "PORTCHANNEL"

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


class AclOrch;

struct AclActionCapabilities
{
    std::set<sai_acl_action_type_t> actionList;
    bool isActionListMandatoryOnTableCreation {false};
};

using AclRuleAttrLookupT = std::map<std::string, sai_acl_entry_attr_t>;
using AclRangeTypeLookupT = std::map<std::string, sai_acl_range_type_t>;
using AclBindPointTypeLookupT = std::map<std::string, sai_acl_bind_point_type_t>;
using AclIpTypeLookupT = std::map<std::string, sai_acl_ip_type_t>;
using AclDtelFlowOpTypeLookupT = std::map<std::string, sai_acl_dtel_flow_op_t>;
using AclPacketActionLookupT = std::map<std::string, sai_packet_action_t>;
using AclRangePropertiesT = std::tuple<sai_acl_range_type_t, int, int>;
using AclActionEnumValuesCapabilitiesT = std::map<sai_acl_action_type_t, std::set<int32_t>>;
using AclCapabilitiesT = std::map<AclStageTypeT, AclActionCapabilities>;

class AclCapability
{
public:
    AclCapability(SwitchOrch* switchOrch);

    bool isCombinedMirrorV6Table() const;
    bool isAclMirrorV6Supported() const;
    bool isAclMirrorV4Supported() const;
    bool isAclMirrorTableSupported(std::string type) const;
    bool isAclActionListMandatoryOnTableCreation(AclStageTypeT stage) const;
    bool isAclActionSupported(AclStageTypeT stage, sai_acl_action_type_t action) const;
    bool isAclActionEnumValueSupported(sai_acl_action_type_t action, sai_acl_action_parameter_t param) const;
    
private:
    void queryMirrorTableCapability();
    void queryAclActionCapability();
    void initDefaultAclActionCapabilities(AclStageTypeT);
    void putAclActionCapabilityInDB(AclStageTypeT);

    template<typename AclActionAttrLookupT>
    void queryAclActionAttrEnumValues(const std::string& action_name,
                                      const AclRuleAttrLookupT& ruleAttrLookupMap,
                                      const AclActionAttrLookupT lookupMap);

private:
    SwitchOrch *m_switchOrch = nullptr;

    bool m_isCombinedMirrorV6Table = true;
    std::map<std::string, bool> m_mirrorTableCapabilities;

    AclCapabilitiesT m_aclCapabilities;
    AclActionEnumValuesCapabilitiesT m_aclEnumActionCapabilities;
};

class AclTableType
{
public:
    std::string getName() const;
    const std::set<sai_acl_bind_point_type_t>& getBindPointTypes() const;
    const std::set<sai_acl_table_attr_t>& getMatches() const;
    const std::set<sai_acl_range_type_t>& getRangeTypes() const;
    const std::set<sai_acl_action_type_t>& getActions() const;

private:
    friend class AclTableTypeBuilder;

    std::string name;
    std::set<sai_acl_bind_point_type_t> bpointTypes;
    std::set<sai_acl_table_attr_t> enabledMatches;
    std::set<sai_acl_range_type_t> rangeTypes;
    std::set<sai_acl_action_type_t> aclAcitons;
};

class AclTableTypeBuilder
{
public:
    AclTableTypeBuilder& withName(std::string name);
    AclTableTypeBuilder& withBindPointType(sai_acl_bind_point_type_t bpointType);
    AclTableTypeBuilder& withEnabledMatch(sai_acl_table_attr_t matchField);
    AclTableTypeBuilder& withAction(sai_acl_action_type_t action);
    AclTableTypeBuilder& withRangeMatch(sai_acl_range_type_t rangeType);
    AclTableType build();

private:
    AclTableType m_tableType;
};

class AclTableTypeParser
{
public:
    bool parse(
        const std::string& key,
        const vector<swss::FieldValueTuple>& fieldValues,
        AclTableTypeBuilder& builder
    );
private:
    bool parseAclTableTypeMatches(const std::string& value, AclTableTypeBuilder& builder);
    bool parseAclTableTypeActions(const std::string& value, AclTableTypeBuilder& builder);
    bool parseAclTableTypeBindPointTypes(const std::string& value, AclTableTypeBuilder& builder);
};

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
    static std::map<AclRangePropertiesT, AclRange*> m_ranges;
};

struct AclRuleCounters
{
    uint64_t packets;
    uint64_t bytes;

    AclRuleCounters(uint64_t p = 0, uint64_t b = 0) :
        packets(p),
        bytes(b)
    {
    }

    AclRuleCounters(const AclRuleCounters& rhs) :
        packets(rhs.packets),
        bytes(rhs.bytes)
    {
    }

    AclRuleCounters& operator +=(const AclRuleCounters& rhs)
    {
        packets += rhs.packets;
        bytes += rhs.bytes;
        return *this;
    }
};

class AclTable;

class AclRule
{
public:
    AclRule(
        AclOrch *pAclOrch,
        std::string rule,
        std::string table,
        bool createCounter = true
    );
    virtual ~AclRule() = default;

    virtual bool setPriority(std::string field, std::string value);
    virtual bool setMatch(std::string field, std::string value);
    virtual bool setAction(std::string field, std::string value);

    bool processIpType(std::string type, sai_uint32_t &ip_type);
    inline static void setRulePriorities(sai_uint32_t min, sai_uint32_t max)
    {
        m_minPriority = min;
        m_maxPriority = max;
    }

    virtual bool create();
    virtual bool remove();
    virtual bool validate();

    virtual void onUpdate(SubjectType, void *) = 0;
    virtual void updateInPorts();

    virtual bool enableCounter();
    virtual bool disableCounter();

    virtual AclRuleCounters getCounters();

    std::string getId() const;
    std::string getTableId() const;
    sai_object_id_t getCounterOid() const;
    vector<sai_object_id_t> getInPorts() const;

    static shared_ptr<AclRule> makeShared(
        AclOrch *acl,
        MirrorOrch *mirror,
        DTelOrch *dtel,
        const std::string& rule,
        const std::string& table,
        const swss::KeyOpFieldsValuesTuple& kofvt
    );


protected:
    virtual bool createCounter();
    virtual bool removeCounter();
    virtual bool removeRanges();

    static sai_uint32_t m_minPriority;
    static sai_uint32_t m_maxPriority;

    uint32_t m_priority;

    std::map<sai_acl_entry_attr_t, sai_attribute_value_t> m_matches;
    std::map<sai_acl_entry_attr_t, sai_attribute_value_t> m_actions;

    vector<sai_object_id_t> m_inPorts;
    vector<sai_object_id_t> m_outPorts;

    AclOrch *m_pAclOrch;
    std::string m_id;
    std::string m_tableId;
    const AclTable* m_pTable;

    sai_object_id_t m_ruleOid;
    sai_object_id_t m_counterOid;

private:
    bool m_createCounter;
};

class AclRulePacket: public AclRule
{
public:
    AclRulePacket(
        AclOrch *pAclOrch,
        std::string rule,
        std::string table,
        bool createCounter = true
    );

    bool create() override;
    bool remove() override;
    bool validate() override;

    bool setAction(std::string field, std::string value) override;

    void onUpdate(SubjectType, void *) override;

protected:
    sai_object_id_t getRedirectObjectId(const std::string& redirect_param);
    void decreaseNextHopRefCount();

private:
    std::string m_redirect_target_next_hop;
    std::string m_redirect_target_next_hop_group;
};

class AclRuleMirror: public AclRule
{
public:
    AclRuleMirror(
        AclOrch *pAclOrch,
        MirrorOrch *pMirrorOrch,
        std::string rule,
        std::string table
    );

    bool create() override;
    bool remove() override;
    bool validate() override;

    bool setAction(std::string field, std::string value) override;

    void onUpdate(SubjectType, void *) override;

    AclRuleCounters getCounters() override;

protected:
    bool m_state {false};
    std::string m_sessionName;
    AclRuleCounters counters;
    MirrorOrch *m_pMirrorOrch {nullptr};
};

class AclRuleDTelFlowWatchListEntry: public AclRule
{
public:
    AclRuleDTelFlowWatchListEntry(
        AclOrch *pAclOrch,
        DTelOrch *pDTelOrch,
        std::string rule,
        std::string table
    );

    bool create() override;
    bool remove() override;
    bool validate() override;

    bool setAction(std::string field, std::string value) override;

    void onUpdate(SubjectType, void *) override;

private:
    DTelOrch *m_pDTelOrch;
    std::string m_intSessionId;
    bool INT_enabled;
    bool INT_session_valid;
};

class AclRuleDTelDropWatchListEntry: public AclRule
{
public:
    AclRuleDTelDropWatchListEntry(
        AclOrch *pAclOrch,
        DTelOrch *pDTelOrch,
        std::string rule,
        std::string table
    );

    bool validate();

    bool setAction(std::string field, std::string value) override;

    void onUpdate(SubjectType, void *) override;

private:
    DTelOrch *m_pDTelOrch;
};

class AclTable
{
public:
    AclTable(AclOrch *pAclOrch, std::string id) noexcept;
    AclTable(AclOrch *pAclOrch) noexcept;

    sai_object_id_t getOid() const;
    std::string getName() const;
    const AclTableType& getTableType() const;
    const std::string& getDescription() const;
    AclStageTypeT getStage() const;
    AclRule* getAclRule(std::string ruleName) const;
    const std::set<std::string>& getPorts() const;

    bool isOneOfDefaultL3MirrorTables() const;
    bool isDefaultMirrorV4Table() const;
    bool isDefaultMirrorV6Table() const;
    bool isOneOfDefaultV6Tables() const;

    void setDescription(const std::string &value);
    bool setTableType(const AclTableType &tableType);
    bool setStage(const AclStageTypeT &value);
    bool addPorts(const std::set<std::string> &value);
    bool removePorts(const std::set<std::string> &value);

    bool validate() const;

    bool create();
    bool remove();

    bool validateAclRuleMatch(sai_attribute_t attr) const;
    bool validateAclRuleAction(sai_attribute_t attr) const;

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
    bool remove(std::string rule_id);
    // Remove all rules from the ACL table
    bool clear();
    // Update table subject to changes
    void onUpdate(SubjectType, void *);
    // Update table based on port change update 
    void onPortChangeUpdate(const PortUpdate& update);

private:
    /* ACL table configuration properties */
    std::string id;
    std::string description;
    std::set<std::string> portSet;
    AclTableType type;
    AclStageTypeT stage {ACL_STAGE_INGRESS};

    AclOrch *m_pAclOrch = nullptr;
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;
    // Map port oid to group member oid
    std::map<sai_object_id_t, sai_object_id_t> ports;
    // Map rule name to rule data
    std::map<std::string, shared_ptr<AclRule>> rules;
};

class AclOrch : public Orch, public Observer
{
public:
    AclOrch(vector<TableConnector>& connectors,
            SwitchOrch              *switchOrch,
            PortsOrch               *portOrch,
            MirrorOrch              *mirrorOrch,
            NeighOrch               *neighOrch,
            RouteOrch               *routeOrch,
            DTelOrch                *dTelOrch = nullptr);
    ~AclOrch();

    void update(SubjectType, void *);

    AclTable* getAclTable(const std::string& tableId);
    sai_object_id_t getTableById(std::string table_id);
    AclTable* getTableByOid(sai_object_id_t oid);
    const AclTableType* getAclTableType(const std::string& tableTypeName) const;
    static swss::Table& getCountersTable();

    // FIXME: Add getters for them? I'd better to add a common directory of orch objects and use it everywhere
    MirrorOrch *m_mirrorOrch;
    NeighOrch *m_neighOrch;
    RouteOrch *m_routeOrch;
    DTelOrch *m_dTelOrch;

    bool addAclTable(AclTable &aclTable);
    bool removeAclTable(std::string table_id);
    bool updateAclTable(AclTable &currentTable, AclTable &newTable);
    bool updateAclTable(std::string table_id, AclTable &table);
    bool addAclTableType(const AclTableType& tableType);
    bool removeAclTableType(const std::string& tableTypeName);
    bool addAclRule(shared_ptr<AclRule> aclRule, std::string table_id);
    bool removeAclRule(std::string table_id, std::string rule_id);
    bool updateAclRule(std::string table_id, std::string rule_id, std::string field, void *data, bool oper);
    bool updateAclRule(std::string table_id, std::string rule_id, bool enableCounter);
    AclRule* getAclRule(std::string table_id, std::string rule_id);
    const AclCapability& getCapability() const;

    using Orch::doTask;  // Allow access to the basic doTask
    std::map<sai_object_id_t, AclTable>  getAclTables();

private:
    SwitchOrch *m_switchOrch;
    void doTask(Consumer &consumer);
    void doAclTableTask(Consumer &consumer);
    void doAclRuleTask(Consumer &consumer);
    void doAclTableTypeTask(Consumer &consumer);
    void doTask(SelectableTimer &timer);
    void init(vector<TableConnector>& connectors, PortsOrch *portOrch, MirrorOrch *mirrorOrch, NeighOrch *neighOrch, RouteOrch *routeOrch);
    void initDefaultTableTypes();

    bool createBindAclTable(AclTable &aclTable);
    bool bindAclTable(AclTable &aclTable, bool bind = true);
    bool deleteUnbindAclTable(sai_object_id_t table_oid);

    bool isAclTableTypeUpdated(std::string table_type, AclTable &aclTable);
    bool processAclTableType(std::string type, AclTable &table);
    bool isAclTableStageUpdated(AclStageTypeT acl_stage, AclTable &aclTable);
    bool processAclTableStage(std::string stage, AclTable &aclTable);
    bool processAclTablePorts(std::string portList, AclTable &aclTable);
    bool validateAclTable(AclTable &aclTable);
    bool updateAclTablePorts(AclTable &newTable, AclTable &curTable);
    void createDTelWatchListTables();
    void deleteDTelWatchListTables();

    std::map<std::string, AclTableType> m_AclTableTypes;
    std::map<sai_object_id_t, AclTable> m_AclTables;

    static DBConnector m_db;
    static Table m_countersTable;

    AclCapability capability;

    std::map<AclStageTypeT, std::string> m_mirrorTableId;
    std::map<AclStageTypeT, std::string> m_mirrorV6TableId;
};

#endif /* SWSS_ACLORCH_H */
