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
        else if (field == "protocol")
        {
            m_isSetOperation = true;
            m_protocol = value;
        }
    }
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
