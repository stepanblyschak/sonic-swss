#pragma once

#include <cassert>

#include <swss/selectable.h>
#include <libnl3/netlink/netlink.h>

#include "fpm/fpm.h"

namespace swss
{

/**
 * @brief FPM zebra communication interface
 */
class FpmInterface : public Selectable
{
public:
    /**
     * @brief Send netlink message through FPM socket
     * @param msg Netlink message
     * @return Amount of bytes sent or negative value on error
     */
    virtual ssize_t send(nl_msg* msg) = 0;
};

}
