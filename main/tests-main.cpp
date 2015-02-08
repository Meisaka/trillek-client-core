#include <gtest/gtest.h>

#include "trillek-game.hpp"

#include "tests/PropertyTest.h"
#include "tests/AtomicQueueTest.h"
#include "tests/AtomicMapTest.h"
#include "tests/MapArrayTest.h"

#include "tests/ResourceSystemTest.h"
#include "tests/UtilityTest.h"
#include "tests/DecompressorTest.h"
#include "tests/ImageLoaderTest.h"
#include "tests/transform-system-test.h"
#include "tests/bitmap-test.hpp"
#include "tests/rewindable-map-test.hpp"
#include "tests/crypto-test.h"
#include "tests/VMAC-stream-hasher-test.h"
#include "tests/ESIGN-signature-test.h"
#include "tests/fifo-allocator-test.hpp"
#include "tests/stream-allocator-test.hpp"

size_t gAllocatedSize = 0;

int main(int argc, char **argv) {
    trillek::TrillekGame::Initialize();
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
