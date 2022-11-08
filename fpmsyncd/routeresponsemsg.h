#pragma once

#include <swss/table.h>
#include <swss/ipprefix.h>
#include <swss/tokenize.h>
#include <swss/converter.h>
#include <swss/json.h>

#include <string>
#include <vector>

#include <iostream>

class RouteResponseMsg
{
public:
    RouteResponseMsg(const std::string& key, const std::vector<swss::FieldValueTuple>& fieldValues);

    bool isSetOperation() const
    {
        return m_isSetOperation;
    }

    bool isOperationSuccessful() const
    {
        return (m_errString == "SWSS_RC_SUCCESS");
    }

    const std::string& getErrorMessage() const
    {
        return m_errString;
    }

    const std::string& getVrf() const
    {
        return m_vrfName;
    }

    const swss::IpPrefix& getPrefix() const
    {
        return m_prefix;
    }

    const std::string& getProtocol() const
    {
        return m_protocol;
    }

private:
    void initVrfAndPrefix(const std::string& key);
    void initRouteFields(const std::vector<swss::FieldValueTuple>& fieldValues);

    bool m_isSetOperation{false};
    std::string m_errString;

    std::string m_vrfName;
    swss::IpPrefix m_prefix;

    std::string m_protocol{};
};
