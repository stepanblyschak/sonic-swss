#ifndef SWSS_PORT_H
#define SWSS_PORT_H

extern "C" {
#include "sai.h"
}

#include <set>
#include <string>
#include <vector>
#include <map>

#define DEFAULT_PORT_VLAN_ID    1
#define DEFAULT_MTU              9100

namespace swss {

struct VlanMemberEntry
{
    sai_object_id_t            vlan_member_id;
    sai_vlan_tagging_mode_t    vlan_mode;
};

typedef std::map<sai_vlan_id_t, VlanMemberEntry> vlan_members_t;

struct VlanInfo
{
    sai_object_id_t     vlan_oid;
    sai_vlan_id_t       vlan_id;
};

class Port
{
public:
    enum Type {
        CPU,
        PHY,
        MGMT,
        LOOPBACK,
        VLAN,
        LAG,
        UNKNOWN
    } ;

    Port() {};
    Port(std::string alias, Type type) :
            m_alias(alias), m_type(type) {};

    inline bool operator<(const Port &o) const
    {
        return m_alias < o.m_alias;
    }

    inline bool operator==(const Port &o) const
    {
        return m_alias == o.m_alias;
    }

    inline bool operator!=(const Port &o) const
    {
        return !(*this == o);
    }

    std::string         m_alias;
    Type                m_type;
    int                 m_index = 0;    // PHY_PORT: index
    uint32_t            m_mtu = DEFAULT_MTU;
    uint32_t            m_speed = 0;    // Mbps
    bool                m_autoneg = 0;
    sai_object_id_t     m_port_id = 0;
    sai_port_fec_mode_t m_fec_mode = SAI_PORT_FEC_MODE_NONE;
    VlanInfo            m_vlan_info;
    sai_object_id_t     m_bridge_port_id = 0;   // TODO: port could have multiple bridge port IDs
    sai_vlan_id_t       m_port_vlan_id = DEFAULT_PORT_VLAN_ID;  // Port VLAN ID
    sai_object_id_t     m_rif_id = 0;
    sai_object_id_t     m_vr_id = 0;
    sai_object_id_t     m_hif_id = 0;
    sai_object_id_t     m_lag_id = 0;
    sai_object_id_t     m_lag_member_id = 0;
    sai_object_id_t     m_ingress_acl_table_group_id = 0;
    sai_object_id_t     m_egress_acl_table_group_id = 0;
    vlan_members_t      m_vlan_members;
    sai_port_oper_status_t m_oper_status = SAI_PORT_OPER_STATUS_UNKNOWN;
    std::set<std::string> m_members;
    std::vector<sai_object_id_t> m_queue_ids;
    std::vector<sai_object_id_t> m_priority_group_ids;
    sai_port_priority_flow_control_mode_t m_pfc_asym = SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED;
    uint8_t m_pfc_bitmask = 0;
};

}

#endif /* SWSS_PORT_H */
