#pragma once

extern "C"
{
#include <sai.h>
#include <saimetadata.h>
}

#include <string>

class SaiAttr
{
public:
    SaiAttr() = default;

    SaiAttr(sai_object_type_t objectType, const sai_attribute_t& attr);
    SaiAttr(const SaiAttr& other);
    SaiAttr(const SaiAttr&& other);
    SaiAttr& operator=(const SaiAttr& other);
    SaiAttr& operator=(const SaiAttr&& other);
    virtual ~SaiAttr();

    bool operator<(const SaiAttr& other) const;

    const sai_attribute_t& getSaiAttr() const;
    std::string toString() const;
    sai_attr_id_t getAttrId() const;

private:

    void initializeFrom(
        sai_object_type_t objectType,
        const sai_attr_metadata_t& meta,
        const sai_attribute_t& attr);
    void swap(const SaiAttr&& other);

    sai_object_type_t m_objectType;
    const sai_attr_metadata_t* m_meta;
    sai_attribute_t m_attr;
    std::string m_serializedAttr;
};
