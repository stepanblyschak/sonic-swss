#include "fpmsyncd/routefeedbackchannel.h"

#include <netlink/route/route.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace swss;

using ::testing::_;

TEST(FpmSyncd, RouteResponseMsgV4)
{
    RouteResponseMsg msg("1.0.0.0/24", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"state_attrs", R"#(["protocol", "bgp", "nexthop", "2.2.2.2,3.3.3.3", "ifname", "Ethernet0,Ethernet4", "weight", "1,1"])#"},
    });

    EXPECT_TRUE(msg.isSetOperation());
    EXPECT_TRUE(msg.isOperationSuccessful());
    EXPECT_EQ(msg.getPrefix().to_string(), "1.0.0.0/24");
    EXPECT_EQ(msg.getVrf(), "");
    EXPECT_EQ(msg.getProtocol(), "bgp");
    ASSERT_EQ(msg.getNextHops().size(), 2);
    EXPECT_EQ(msg.getNextHops()[0].address.to_string(), "2.2.2.2");
    EXPECT_EQ(msg.getNextHops()[1].address.to_string(), "3.3.3.3");
    EXPECT_EQ(msg.getNextHops()[0].ifaceName, "Ethernet0");
    EXPECT_EQ(msg.getNextHops()[1].ifaceName, "Ethernet4");
    EXPECT_EQ(msg.getNextHops()[0].weight, 1);
    EXPECT_EQ(msg.getNextHops()[1].weight, 1);
}

TEST(FpmSyncd, RouteResponseMsgV4WithVrf)
{
    RouteResponseMsg msg("Vrf0:1.0.0.0/24", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"state_attrs", R"#(["protocol", "200", "nexthop", "2.2.2.2,3.3.3.3", "ifname", "Ethernet0,Ethernet4", "weight", "1,1"])#"},
    });

    EXPECT_TRUE(msg.isSetOperation());
    EXPECT_TRUE(msg.isOperationSuccessful());
    EXPECT_EQ(msg.getPrefix().to_string(), "1.0.0.0/24");
    EXPECT_EQ(msg.getProtocol(), "200");
    EXPECT_EQ(msg.getVrf(), "Vrf0");
    ASSERT_EQ(msg.getNextHops().size(), 2);
    EXPECT_EQ(msg.getNextHops()[0].address.to_string(), "2.2.2.2");
    EXPECT_EQ(msg.getNextHops()[1].address.to_string(), "3.3.3.3");
    EXPECT_EQ(msg.getNextHops()[0].ifaceName, "Ethernet0");
    EXPECT_EQ(msg.getNextHops()[1].ifaceName, "Ethernet4");
    EXPECT_EQ(msg.getNextHops()[0].weight, 1);
    EXPECT_EQ(msg.getNextHops()[1].weight, 1);
}

TEST(FpmSyncd, RouteResponseMsgV6)
{
    RouteResponseMsg msg("1::/64", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"state_attrs", R"#(["nexthop", "2::2,3::3", "ifname", "Ethernet0,Ethernet4", "weight", "1,1"])#"},
    });

    EXPECT_TRUE(msg.isSetOperation());
    EXPECT_TRUE(msg.isOperationSuccessful());
    EXPECT_EQ(msg.getPrefix().to_string(), "1::/64");
    EXPECT_EQ(msg.getVrf(), "");
    ASSERT_EQ(msg.getNextHops().size(), 2);
    EXPECT_EQ(msg.getNextHops()[0].address.to_string(), "2::2");
    EXPECT_EQ(msg.getNextHops()[1].address.to_string(), "3::3");
    EXPECT_EQ(msg.getNextHops()[0].ifaceName, "Ethernet0");
    EXPECT_EQ(msg.getNextHops()[1].ifaceName, "Ethernet4");
    EXPECT_EQ(msg.getNextHops()[0].weight, 1);
    EXPECT_EQ(msg.getNextHops()[1].weight, 1);
}

TEST(FpmSyncd, RouteResponseMsgV6WithVrf)
{
    RouteResponseMsg msg("Vrf0:1::/64", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"state_attrs", R"#(["nexthop", "2::2,3::3", "ifname", "Ethernet0,Ethernet4", "weight", "1,1"])#"},
    });

    EXPECT_TRUE(msg.isSetOperation());
    EXPECT_TRUE(msg.isOperationSuccessful());
    EXPECT_EQ(msg.getPrefix().to_string(), "1::/64");
    EXPECT_EQ(msg.getVrf(), "Vrf0");
    ASSERT_EQ(msg.getNextHops().size(), 2);
    EXPECT_EQ(msg.getNextHops()[0].address.to_string(), "2::2");
    EXPECT_EQ(msg.getNextHops()[1].address.to_string(), "3::3");
    EXPECT_EQ(msg.getNextHops()[0].ifaceName, "Ethernet0");
    EXPECT_EQ(msg.getNextHops()[1].ifaceName, "Ethernet4");
    EXPECT_EQ(msg.getNextHops()[0].weight, 1);
    EXPECT_EQ(msg.getNextHops()[1].weight, 1);
}

class MockFpm : public FpmInterface
{
public:
    MOCK_METHOD(ssize_t, send, (nl_msg*), (override));
    MOCK_METHOD(int, getFd, (), (override));
    MOCK_METHOD(uint64_t, readData, (), (override));
};

class FpmSyncdResponseTest : public ::testing::Test
{
public:
    void SetUp() override
    {
        EXPECT_EQ(rtnl_route_read_protocol_names(DEFAULT_RT_PROTO_PATH), 0);
    }

    void TearDown() override
    {
    }

    RouteFeedbackChannel m_feedbackChannel;
    MockFpm m_mockFpm;
};

TEST_F(FpmSyncdResponseTest, RouteResponseFeedbackV4)
{
    RouteResponseMsg msg("1.0.0.0/24", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"state_attrs", R"#(["protocol", "bgp", "nexthop", "2.2.2.2,3.3.3.3", "ifname", "Ethernet0,Ethernet4", "weight", "1,1"])#"},
    });

    // Expect the message to zebra is sent
    EXPECT_CALL(m_mockFpm, send(_)).WillOnce([&](nl_msg* msg) -> ssize_t {
        rtnl_route* routeObject;
        rtnl_route_parse(nlmsg_hdr(msg), &routeObject);

        // table is 0 when no in default VRF
        EXPECT_EQ(rtnl_route_get_table(routeObject), 0);
        EXPECT_EQ(rtnl_route_get_protocol(routeObject), RTPROT_BGP);

        // Offload flag is set
        EXPECT_EQ(rtnl_route_get_flags(routeObject) & RTM_F_OFFLOAD, RTM_F_OFFLOAD);
        EXPECT_EQ(rtnl_route_get_nnexthops(routeObject), 2);

        return 1;
    });

    m_feedbackChannel.sendRouteOffloadMessage(m_mockFpm, msg);
}

TEST_F(FpmSyncdResponseTest, RouteResponseFeedbackV4Vrf)
{
    RouteResponseMsg msg("Vrf0:1.0.0.0/24", {
        {"err_str", "SWSS_RC_SUCCESS"},
        {"state_attrs", R"#(["protocol", "200", "nexthop", "2.2.2.2,3.3.3.3", "ifname", "Ethernet0,Ethernet4", "weight", "1,1"])#"},
    });

    // Expect the message to zebra is sent
    EXPECT_CALL(m_mockFpm, send(_)).WillOnce([&](nl_msg* msg) -> ssize_t {
        rtnl_route* routeObject;
        rtnl_route_parse(nlmsg_hdr(msg), &routeObject);

        // table is 42 (returned by fake link cache) when in non default VRF
        EXPECT_EQ(rtnl_route_get_table(routeObject), 42);
        EXPECT_EQ(rtnl_route_get_protocol(routeObject), 200);

        // Offload flag is set
        EXPECT_EQ(rtnl_route_get_flags(routeObject) & RTM_F_OFFLOAD, RTM_F_OFFLOAD);
        EXPECT_EQ(rtnl_route_get_nnexthops(routeObject), 2);

        return 1;
    });

    m_feedbackChannel.sendRouteOffloadMessage(m_mockFpm, msg);
}

