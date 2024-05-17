#include <string>
#include <vector>

#include "response_publisher.h"

ResponsePublisher::ResponsePublisher(const std::string& dbName, bool buffered, bool db_write_thread) :
    m_db(std::make_unique<swss::DBConnector>(dbName, 0)), m_buffered(buffered) {}

ResponsePublisher::~ResponsePublisher() {}

void ResponsePublisher::publish(
    const std::string& table, const std::string& key,
    const std::vector<swss::FieldValueTuple>& intent_attrs,
    const ReturnCode& status,
    const std::vector<swss::FieldValueTuple>& state_attrs, bool replace) {}

void ResponsePublisher::publish(
    const std::string& table, const std::string& key,
    const std::vector<swss::FieldValueTuple>& intent_attrs,
    const ReturnCode& status, bool replace) {}

void ResponsePublisher::writeToDB(
    const std::string& table, const std::string& key,
    const std::vector<swss::FieldValueTuple>& values, const std::string& op,
    bool replace) {}

void ResponsePublisher::flush() {}

void ResponsePublisher::setBuffered(bool buffered) {}
