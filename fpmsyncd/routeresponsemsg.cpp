#include "fpmsyncd/routeresponsemsg.h"

RouteResponseMsg::RouteResponseMsg(const std::string& key, const std::vector<swss::FieldValueTuple>& fieldValues)
{
    initVrfAndPrefix(key);

    for (const auto& fieldValue: fieldValues)
    {
        std::string field = fvField(fieldValue);
        std::string value = fvValue(fieldValue);

        if (field == "err_str")
        {
            m_errString = value;
        }
        else if (field == "state_attrs")
        {
            std::vector<swss::FieldValueTuple> stateFieldValues;
            swss::JSon::readJson(value, stateFieldValues);

            if (!stateFieldValues.empty())
            {
                // State attributes presence indicates a set operation
                m_isSetOperation = true;
            }

            initRouteFields(stateFieldValues);
        }
    }
}

RouteResponseMsg::RouteResponseMsg(const std::string& key, const std::string& errString, const std::vector<swss::FieldValueTuple>& fieldValues) :
    m_errString(errString),
    m_isSetOperation(true)
{
    initVrfAndPrefix(key);
    initRouteFields(fieldValues);
}

void RouteResponseMsg::initVrfAndPrefix(const std::string& key)
{
    std::string prefixString;

    auto colon = key.find(':');
    if (colon != std::string::npos && key.substr(0, colon).find("Vrf") != std::string::npos)
    {
        m_vrfName = key.substr(0, colon);
        prefixString = key.substr(colon + 1);
    }
    else
    {
        prefixString = key;
    }

    m_prefix = swss::IpPrefix{prefixString};
}

void RouteResponseMsg::initRouteFields(const std::vector<swss::FieldValueTuple>& fieldValues)
{
    std::vector<std::string> nextHops;
    std::vector<std::string> ifaceNames;
    std::vector<uint8_t> weights;

    for (const auto& fieldValue: fieldValues)
    {
        std::string field = fvField(fieldValue);
        std::string value = fvValue(fieldValue);

        if (field == "protocol")
        {
            m_protocol = value;
        }
        else if (field == "nexthop")
        {
            nextHops = swss::tokenize(value, ',');
        }
        else if (field == "ifname")
        {
            ifaceNames = swss::tokenize(value, ',');
        }
        else if (field == "weight")
        {
            auto weightsStr = swss::tokenize(value, ',');

            for (const auto& weightStr: weightsStr)
            {
                weights.emplace_back(swss::to_uint<uint8_t>(weightStr));
            }
        }
    }

    for (size_t i = 0; i < nextHops.size(); i++)
    {
        uint8_t weight{};
        // if weight is set in DB
        if (!weights.empty())
        {
            weight = weights.at(i);
        }
        m_nextHops.emplace_back(NextHop{nextHops[i], ifaceNames.at(i), weight});
    }
}
