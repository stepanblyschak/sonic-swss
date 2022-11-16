#include "fpmsyncd/routesync.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace swss;

using ::testing::_;

class MockFpm : public FpmInterface
{
public:
    MOCK_METHOD(bool, send, (nlmsghdr*), (override));
    MOCK_METHOD(int, getFd, (), (override));
    MOCK_METHOD(uint64_t, readData, (), (override));
};

class FpmSyncdResponseTest : public ::testing::Test
{
public:
    void SetUp() override
    {
        EXPECT_EQ(rtnl_route_read_protocol_names(DefaultRtProtoPath), 0);
        m_routeSync.m_fpmInterface = &m_mockFpm;
        m_routeSync.setSuppressionEnabled(true);
    }

    void TearDown() override
    {
    }

    DBConnector m_db{"APPL_DB", 0};
    RedisPipeline m_pipeline{&m_db, 1};
    RouteSync m_routeSync{&m_pipeline};
    MockFpm m_mockFpm;
};


TEST_F(FpmSyncdResponseTest, RouteResponseFeedbackV4)
{
    // Expect the message to zebra is sent
    EXPECT_CALL(m_mockFpm, send(_)).WillOnce([&](nlmsghdr* hdr) -> bool {
        rtnl_route* routeObject{};

        rtnl_route_parse(hdr, &routeObject);

        // table is 0 when no in default VRF
        EXPECT_EQ(rtnl_route_get_table(routeObject), 0);
        EXPECT_EQ(rtnl_route_get_protocol(routeObject), RTPROT_BGP);

        // Offload flag is set
        EXPECT_EQ(rtnl_route_get_flags(routeObject) & RTM_F_OFFLOAD, RTM_F_OFFLOAD);

        return true;
    });

    m_routeSync.onRouteResponse("1.0.0.0/24", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"protocol", "bgp"},
    });
}

TEST_F(FpmSyncdResponseTest, RouteResponseFeedbackV4Vrf)
{
    // Expect the message to zebra is sent
    EXPECT_CALL(m_mockFpm, send(_)).WillOnce([&](nlmsghdr* hdr) -> bool {
        rtnl_route* routeObject{};

        rtnl_route_parse(hdr, &routeObject);

        // table is 42 (returned by fake link cache) when in non default VRF
        EXPECT_EQ(rtnl_route_get_table(routeObject), 42);
        EXPECT_EQ(rtnl_route_get_protocol(routeObject), 200);

        // Offload flag is set
        EXPECT_EQ(rtnl_route_get_flags(routeObject) & RTM_F_OFFLOAD, RTM_F_OFFLOAD);

        return true;
    });

    m_routeSync.onRouteResponse("Vrf0:1.0.0.0/24", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"protocol", "200"},
    });
}
