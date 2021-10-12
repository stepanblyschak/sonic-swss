#pragma once

#include "gearboxutils.h"

#include <string>

void initSaiApi();
void initSaiRedis(const std::string &record_location, const std::string &record_filename);
sai_status_t initSaiPhyApi(swss::gearbox_phy_t *phy);


struct ISaiAttributeValue
{
    virtual sai_attribute_value_t toSaiAttributeValue() = 0;
};

template<typename T>
struct SaiTypeTraits
{
};

template<>
struct SaiTypeTraits<sai_s32_list_t>
{
    using ContainerType = std::vector<int32_t>;
    static sai_attribute_value_t toSaiAttributeValue(ContainerType container)
    {
        sai_attribute_value_t value;
        value.s32list.count = static_cast<uint32_t>(container.size());
        value.s32list.list = container.data();
        return value;
    }
};

template<>
struct SaiTypeTraits<bool>
{
    using ContainerType = bool;
    static sai_attribute_value_t toSaiAttributeValue(ContainerType container)
    {
        sai_attribute_value_t value;
        value.booldata = container;
        return value;
    }
};

template<typename SaiType>
struct SaiAttributeValue : ISaiAttributeValue
{
    typename SaiTypeTraits<SaiType>::ContainerType container;

    SaiAttributeValue(typename SaiTypeTraits<SaiType>::ContainerType container):
        container(container)
    {
        SWSS_LOG_ENTER();
    }

    sai_attribute_value_t toSaiAttributeValue() override
    {
        return SaiTypeTraits<SaiType>::toSaiAttributeValue(container);
    }
};
