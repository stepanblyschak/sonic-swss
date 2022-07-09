#pragma once

#include <string>

#include "dbconnector.h"
#include "table.h"

extern "C"
{
#include "sai.h"
}

namespace swss {

class OidMapper
{
public:
    struct Key
    {
        static constexpr auto fieldSeparator = ':';

        sai_object_type_t objectType {SAI_OBJECT_TYPE_NULL};
        std::string keyName;

        std::string serialize() const;
    };

    OidMapper(swss::DBConnector& db);

    // Sets oid for the given key for the specific object_type.
    void set(_In_ const Key& key, _In_ sai_object_id_t oid);

    // Gets oid for the given key for the SAI object_type.
    sai_object_id_t get(_In_ const Key& key);

    // Get key by SAI OID
    std::string getKeyByOID(_In_ sai_object_id_t oid);

    // Erases oid for the given key for the SAI object_type.
    // This function checks if the reference count is zero or not before the
    // operation.
    void erase(_In_ const Key& key);

    // Checks whether OID mapping exists for the given key for the specific
    // object type.
    bool exists(_In_ const Key& key);

    std::string getSeparator() const { return m_keyToOid.getTableNameSeparator(); }

private:
    swss::Table m_keyToOid;
    swss::Table m_oidToKey;
};

}
