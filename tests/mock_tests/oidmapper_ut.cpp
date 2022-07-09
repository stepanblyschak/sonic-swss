#include "mock_table.h"

#include <oidmapper/oidmapper.h>

#include <gtest/gtest.h>

class OidMapperTest : public ::testing::Test {
protected:
    void SetUp() override {
        ::testing_db::reset();

        m_db = std::make_shared<swss::DBConnector>("APPL_STATE_DB", 0);
        m_oidMapper = std::make_shared<swss::OidMapper>(*m_db);
    }

    std::shared_ptr<swss::DBConnector> m_db;
    std::shared_ptr<swss::OidMapper> m_oidMapper;
};

TEST_F(OidMapperTest, SetGetEraseTest) {
    ASSERT_FALSE(m_oidMapper->exists({SAI_OBJECT_TYPE_PORT, "Ethernet0"}));
    ASSERT_FALSE(m_oidMapper->exists({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}));

    ASSERT_EQ(m_oidMapper->get({SAI_OBJECT_TYPE_PORT, "Ethernet0"}), SAI_NULL_OBJECT_ID);
    ASSERT_EQ(m_oidMapper->get({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}), SAI_NULL_OBJECT_ID);

    sai_object_id_t someOid {0xdeadbeafdeadbeaf};
    sai_object_id_t someOid2 {0xdeadbeaf1234abcd};

    m_oidMapper->set({SAI_OBJECT_TYPE_PORT, "Ethernet0"}, someOid);

    ASSERT_EQ(m_oidMapper->get({SAI_OBJECT_TYPE_PORT, "Ethernet0"}), someOid);

    m_oidMapper->set({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}, someOid2);

    ASSERT_EQ(m_oidMapper->get({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}), someOid2);

    ASSERT_TRUE(m_oidMapper->exists({SAI_OBJECT_TYPE_PORT, "Ethernet0"}));
    ASSERT_TRUE(m_oidMapper->exists({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}));

    ASSERT_EQ(m_oidMapper->getKeyByOID(someOid), "Ethernet0");
    ASSERT_EQ(m_oidMapper->getKeyByOID(someOid2), "DATAACL|RULE0");

    m_oidMapper->erase({SAI_OBJECT_TYPE_PORT, "Ethernet0"});
    m_oidMapper->erase({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"});

    ASSERT_FALSE(m_oidMapper->exists({SAI_OBJECT_TYPE_PORT, "Ethernet0"}));
    ASSERT_FALSE(m_oidMapper->exists({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}));

    ASSERT_EQ(m_oidMapper->getKeyByOID(someOid), "");
    ASSERT_EQ(m_oidMapper->getKeyByOID(someOid2), "");

    ASSERT_FALSE(m_oidMapper->get({SAI_OBJECT_TYPE_PORT, "Ethernet0"}));
    ASSERT_FALSE(m_oidMapper->get({SAI_OBJECT_TYPE_ACL_ENTRY, "DATAACL|RULE0"}));
}
