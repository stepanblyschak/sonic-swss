#include <string>
#include <fstream>

#include "response_publisher.h"
#include "response_publisher_old.h"

#include <benchmark/benchmark.h>

bool gResponsePublisherRecord;
bool gResponsePublisherLogRotate;
std::ofstream gResponsePublisherRecordOfs;
std::string gResponsePublisherRecordFile;

using namespace swss;
using namespace std;

static void BM_newResponsePublisher(benchmark::State& state) {
    ResponsePublisher publisher{};

    for (auto _ : state) {
        publisher.publish("SOME_TABLE", "SOME_KEY", {}, ReturnCode(SAI_STATUS_SUCCESS));
    }
}

static void BM_oldResponsePublisher(benchmark::State& state) {
    old::ResponsePublisher publisher{};

    for (auto _ : state) {
        publisher.publish("SOME_TABLE", "SOME_KEY", {}, ReturnCode(SAI_STATUS_SUCCESS));
    }
}

BENCHMARK(BM_newResponsePublisher);
BENCHMARK(BM_oldResponsePublisher);

BENCHMARK_MAIN();