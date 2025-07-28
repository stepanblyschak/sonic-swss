#include "counternameupdater.h"
#include "hftelorch.h"

#include <swss/logger.h>
#include <sai_serialize.h>

extern HFTelOrch *gHFTOrch;

CounterNameMapUpdater::CounterNameMapUpdater(const std::string &db_name, const std::string &table_name)
    : m_db_name(db_name),
      m_table_name(table_name),
      m_connector(m_db_name, 0),
      m_counters_table(&m_connector, m_table_name)
{
    SWSS_LOG_ENTER();
}

void CounterNameMapUpdater::setCounterNameMap(const std::string &counter_name, sai_object_id_t oid)
{
    SWSS_LOG_ENTER();

    if (gHFTOrch)
    {
        Message msg{
            .m_table_name = m_table_name.c_str(),
            .m_operation = OPERATION::SET,
            .m_set{
                .m_counter_name = counter_name.c_str(),
                .m_oid = oid,
            },
        };
        gHFTOrch->locallyNotify(msg);
    }

    m_counters_table.hset("", counter_name, sai_serialize_object_id(oid));
}

void CounterNameMapUpdater::delCounterNameMap(const std::string &counter_name)
{
    SWSS_LOG_ENTER();

    if (gHFTOrch)
    {
        Message msg{
            .m_table_name = m_table_name.c_str(),
            .m_operation = OPERATION::DEL,
            .m_del{
                .m_counter_name = counter_name.c_str(),
            },
        };
        gHFTOrch->locallyNotify(msg);
    }

    m_counters_table.hdel("", counter_name);
}
