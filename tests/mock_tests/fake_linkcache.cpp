#include <swss/linkcache.h>
#include <swss/logger.h>

static rtnl_link* g_fakeLink;

namespace swss {

LinkCache& LinkCache::getInstance()
{
    static LinkCache cache{};
    return cache;
}

std::string LinkCache::ifindexToName(int ifindex) { return ""; }

rtnl_link* LinkCache::getLinkByName(const char* name)
{
    return g_fakeLink;
}

LinkCache::LinkCache()
{
    g_fakeLink = rtnl_link_alloc();
    rtnl_link_set_ifindex(g_fakeLink, 42);
}

LinkCache::~LinkCache()
{
    rtnl_link_put(g_fakeLink);
}

}
