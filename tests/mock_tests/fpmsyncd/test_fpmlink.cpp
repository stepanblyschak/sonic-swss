#include "fpmsyncd/fpmlink.h"

#include <swss/netdispatcher.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace swss;

using ::testing::_;

class MockMsgHandler : public NetMsg
{
public:
    MOCK_METHOD(void, onMsg, (int, nl_object*), (override));
};

class FpmLinkTest : public ::testing::Test
{
public:
    void SetUp() override
    {
        NetDispatcher::getInstance().registerMessageHandler(RTM_NEWROUTE, &m_mock);
        NetDispatcher::getInstance().registerMessageHandler(RTM_DELROUTE, &m_mock);
    }

    void TearDown() override
    {
        NetDispatcher::getInstance().unregisterMessageHandler(RTM_NEWROUTE);
        NetDispatcher::getInstance().unregisterMessageHandler(RTM_DELROUTE);
    }

    FpmLink m_fpm{nullptr};
    MockMsgHandler m_mock;
};

TEST_F(FpmLinkTest, SingleNlMessageInFpmMessage)
{
    // Single FPM message containing single RTM_NEWROUTE
    unsigned char fpmMsgBuffer[] = {
        0x01, 0x01, 0x00, 0x40, 0x3C, 0x00, 0x00, 0x00, 0x18, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0xE0,
        0x12, 0x6F, 0xC4, 0x02, 0x18, 0x00, 0x00, 0xFE, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05,
        0x00, 0xAC, 0x1E, 0x38, 0xA6, 0x08, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00
    };

    EXPECT_CALL(m_mock, onMsg(_, _)).Times(1);

    m_fpm.processFpmMessage(reinterpret_cast<fpm_msg_hdr_t*>(fpmMsgBuffer));
}

TEST_F(FpmLinkTest, TwoNlMessagesInFpmMessage)
{
    // Single FPM message containing RTM_DELROUTE and RTM_NEWROUTE
    unsigned char fpmMsgBuffer[] = {
        0x01, 0x01, 0x00, 0x6C, 0x2C, 0x00, 0x00, 0x00, 0x19, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x12,
        0x6F, 0xC4, 0x02, 0x18, 0x00, 0x00, 0xFE, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x01, 0x01, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x18, 0x00,
        0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x12, 0x6F, 0xC4, 0x02, 0x18, 0x00, 0x00, 0xFE, 0x02, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x14, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0xAC, 0x1E, 0x38, 0xA7, 0x08, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00
    };

    EXPECT_CALL(m_mock, onMsg(_, _)).Times(2);

    m_fpm.processFpmMessage(reinterpret_cast<fpm_msg_hdr_t*>(fpmMsgBuffer));
}

