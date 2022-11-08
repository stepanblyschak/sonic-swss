#include "routefeedbackchannel.h"

extern "C"
{
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>
}

#include <memory>

namespace
{

/* Helper to create unique pointer with custom destructor */
template<typename T, typename F>
decltype(auto) makeUniqueWithDestructor(T* ptr, F func)
{
    return std::unique_ptr<T, F>(ptr, func);
}

template<typename T>
decltype(auto) makeNlAddr(const T& ip)
{
    nl_addr* addr;
    nl_addr_parse(ip.to_string().c_str(), AF_UNSPEC, &addr);
    return makeUniqueWithDestructor(addr, nl_addr_put);
}

}

namespace swss
{

void RouteFeedbackChannel::sendRouteOffloadMessage(FpmInterface& fpm, const RouteResponseMsg& routeResponse)
{
    SWSS_LOG_ENTER();

    if (!routeResponse.isSetOperation())
    {
        SWSS_LOG_DEBUG("Received response for prefix %s(%s) deletion, ignoring ",
            routeResponse.getPrefix().to_string().c_str(), routeResponse.getVrf().c_str());
        return;
    }

    auto routeObject = makeUniqueWithDestructor(rtnl_route_alloc(), rtnl_route_put);
    auto dstAddr = makeNlAddr(routeResponse.getPrefix());

    rtnl_route_set_dst(routeObject.get(), dstAddr.get());

    auto protocol = rtnl_route_str2proto(routeResponse.getProtocol().c_str());
    if (protocol < 0)
    {
        protocol = swss::to_uint<uint8_t>(routeResponse.getProtocol());
    }

    rtnl_route_set_protocol(routeObject.get(), static_cast<uint8_t>(protocol));
    rtnl_route_set_family(routeObject.get(), routeResponse.getPrefix().isV4() ? AF_INET : AF_INET6);

    unsigned int vrfIfIndex = 0;
    if (!routeResponse.getVrf().empty())
    {
        auto* link = m_linkCache.getLinkByName(routeResponse.getVrf().c_str());
        if (!link)
        {
            SWSS_LOG_DEBUG("Failed to find VRF when constructing response message for prefix %s(%s). "
                "This message is probably outdated", routeResponse.getPrefix().to_string().c_str(),
                routeResponse.getVrf().c_str());
            return;
        }
        vrfIfIndex = rtnl_link_get_ifindex(link);
    }

    rtnl_route_set_table(routeObject.get(), vrfIfIndex);

    unsigned int flags = 0;

    if (routeResponse.isOperationSuccessful())
    {
        flags |= RTM_F_OFFLOAD;
    }

    // Mark route as OFFLOAD
    rtnl_route_set_flags(routeObject.get(), RTM_F_OFFLOAD);

    nl_msg* msg{};
    rtnl_route_build_add_request(routeObject.get(), NLM_F_CREATE, &msg);

    auto ownedMsg = makeUniqueWithDestructor(msg, nlmsg_free);

    // Send to zebra
    if (!fpm.send(ownedMsg.get()))
    {
        SWSS_LOG_ERROR("Failed to send RTM_NEWROUTE message to zebra on prefix %s(%s), errno %s",
            routeResponse.getPrefix().to_string().c_str(), routeResponse.getVrf().c_str(), strerror(errno)
        );
        return;
    }

    SWSS_LOG_DEBUG("Sent response to zebra on prefix %s(%s)",
        routeResponse.getPrefix().to_string().c_str(), routeResponse.getVrf().c_str());
}

}
