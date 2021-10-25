#include "saiattr.h"

#include <swss/logger.h>
#include <sai_serialize.h>

#include <iostream>

SaiAttr::SaiAttr(sai_object_type_t objectType, const sai_attribute_t& attr)
{
    auto meta = sai_metadata_get_attr_metadata(objectType, attr.id);
    if (!meta)
    {
        SWSS_LOG_THROW("Failed to get attribute %d metadata", attr.id);
    }

    initializeFrom(objectType, *meta, attr);
}

SaiAttr::~SaiAttr()
{
    sai_deserialize_free_attribute_value(m_meta->attrvaluetype, m_attr);
}

SaiAttr::SaiAttr(const SaiAttr& other)
{
    initializeFrom(other.m_objectType, *other.m_meta, other.m_attr);
}

SaiAttr& SaiAttr::operator=(const SaiAttr& other)
{
    initializeFrom(other.m_objectType, *other.m_meta, other.m_attr);
    return *this;
}

SaiAttr::SaiAttr(const SaiAttr&& other)
{
    swap(std::move(other));
}

SaiAttr& SaiAttr::operator=(const SaiAttr&& other)
{
    swap(std::move(other));
    return *this;
}

bool SaiAttr::operator<(const SaiAttr& other) const
{
    return m_serializedAttr < other.m_serializedAttr;
}

const sai_attribute_t& SaiAttr::getSaiAttr() const
{
    return m_attr;
}

std::string SaiAttr::toString() const
{
    return m_serializedAttr;
}

sai_attr_id_t SaiAttr::getAttrId() const
{
    return m_attr.id;
}

void SaiAttr::swap(const SaiAttr&& other)
{
    m_objectType = other.m_objectType;
    m_meta = other.m_meta;
    m_attr = other.m_attr;
    m_serializedAttr = other.m_serializedAttr;
}

void SaiAttr::initializeFrom(
    sai_object_type_t objectType,
    const sai_attr_metadata_t& meta,
    const sai_attribute_t& attr)
{
    m_objectType = objectType;
    m_attr.id = attr.id;
    m_meta = &meta;

    m_serializedAttr = sai_serialize_attr_value(*m_meta, attr);

    // deserialize to actually preform a deep copy of attr
    // and attribute value's dynamically allocated lists.
    sai_deserialize_attr_value(m_serializedAttr, *m_meta, m_attr);
}