#pragma once

#include <swss/linkcache.h>

#include "fpmsyncd/fpminterface.h"
#include "fpmsyncd/routeresponsemsg.h"

/* Path to protocol name database provided by iproute2 */
constexpr char* DEFAULT_RT_PROTO_PATH = "/etc/iproute2/rt_protos";

namespace swss
{

class RouteFeedbackChannel
{
public:
    RouteFeedbackChannel() = default;

    /*
     * @brief Constructs an RTM_NEWROUTE netlink message from RouteResponseMsg with offload flag set
     * and sends it through FPM socket.
     *
     * @param fpm FPM interface
     * @param msg RouteResponseMsg object
     */
    void sendRouteOffloadMessage(FpmInterface& fpm, const RouteResponseMsg& msg);
private:
    LinkCache& m_linkCache{LinkCache::getInstance()};
};

}
