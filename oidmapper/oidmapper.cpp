#include "oidmapper.h"

#include "logger.h"
#include "sai_serialize.h"
#include "tokenize.h"

extern "C"
{
#include "sai.h"
}

namespace swss {

std::string OidMapper::Key::serialize() const
{
    return sai_serialize_object_type(objectType) + fieldSeparator + keyName;
}

OidMapper::OidMapper(swss::DBConnector& db): m_keyToOid(&db, "APP_KEY_TO_OID"), m_oidToKey(&db, "APP_OID_TO_KEY")
{
}

void OidMapper::set(_In_ const Key& key, _In_ sai_object_id_t oid)
{
    SWSS_LOG_ENTER();

    auto serializedOid = sai_serialize_object_id(oid);

    m_keyToOid.hset("", key.serialize(), serializedOid);
    m_oidToKey.hset("", serializedOid, key.keyName);
}

sai_object_id_t OidMapper::get(_In_ const Key& key)
{
    SWSS_LOG_ENTER();

    sai_object_id_t oid{SAI_NULL_OBJECT_ID};
    std::string serializedOid;

    if (!m_keyToOid.hget("", key.serialize(), serializedOid))
    {
        return oid;
    }

    sai_deserialize_object_id(serializedOid, oid);

    return oid;
}

void OidMapper::erase(_In_ const Key& key)
{
    SWSS_LOG_ENTER();

    auto oid = get(key);
    if (oid != SAI_NULL_OBJECT_ID)
    {
        m_keyToOid.hdel("", key.serialize());
        m_oidToKey.hdel("", sai_serialize_object_id(oid));
    }
}

bool OidMapper::exists(_In_ const Key& key)
{
    SWSS_LOG_ENTER();

    std::string serializedOid;
    return m_keyToOid.hget("", key.serialize(), serializedOid);
}

std::string OidMapper::getKeyByOID(_In_ sai_object_id_t oid)
{
    SWSS_LOG_ENTER();

    std::string key;
    m_oidToKey.hget("", sai_serialize_object_id(oid), key);

    return key;
}

}