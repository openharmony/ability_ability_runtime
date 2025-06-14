/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include <gtest/gtest.h>

#include "dynamic_loader.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EtsEnv {
class DynamicLoaderTest : public testing::Test {
public:
    DynamicLoaderTest()
    {}
    ~DynamicLoaderTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    static constexpr const char* TEST_LIB = "libc.so";
    static constexpr const char* TEST_SYMBOL = "printf";
};

void DynamicLoaderTest::SetUpTestCase(void)
{
    Dl_namespace ns;
    DynamicInitNamespace(&ns, nullptr, "", "ets_app");
}

void DynamicLoaderTest::TearDownTestCase(void)
{}

void DynamicLoaderTest::SetUp(void)
{
    char* errorBuf = const_cast<char*>(DynamicGetError());
    if (errorBuf != nullptr) {
        errorBuf[0] = '\0';
    }
    (void)dlerror();
}

void DynamicLoaderTest::TearDown(void)
{}

/**
 * @tc.name: DynamicLoaderTestLoadLibrary_0100
 * @tc.desc: DynamicLoaderTest test for dynamic_load_library.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestLoadLibrary_0100, TestSize.Level1)
{
    Dl_namespace ns;
    DynamicInitNamespace(&ns, nullptr, "", "test_namespace");

    void* handle = DynamicLoadLibrary(&ns, TEST_LIB, RTLD_LAZY);
    EXPECT_NE(handle, nullptr);
    EXPECT_STREQ(DynamicGetError(), "");

    if (handle) {
        DynamicFreeLibrary(handle);
    }
}

/**
 * @tc.name: DynamicLoaderTestLoadLibrary_0200
 * @tc.desc: DynamicLoaderTest test for dynamic_load_library.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestLoadLibrary_0200, TestSize.Level1)
{
    Dl_namespace ns;
    DynamicInitNamespace(&ns, nullptr, "", "test_namespace");

    void* handle = DynamicLoadLibrary(&ns, "invalid_lib.so", RTLD_LAZY);
    EXPECT_EQ(handle, nullptr);
    EXPECT_STRNE(DynamicGetError(), "");
}

/**
 * @tc.name: DynamicLoaderTestLoadLibrary_0300
 * @tc.desc: DynamicLoaderTest test for dynamic_load_library.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestLoadLibrary_0300, TestSize.Level1)
{
    void* handle = DynamicLoadLibrary(nullptr, TEST_LIB, RTLD_LAZY);
    EXPECT_NE(handle, nullptr);
    EXPECT_STREQ(DynamicGetError(), "");

    if (handle) {
        DynamicFreeLibrary(handle);
    }
}

/**
 * @tc.name: DynamicLoaderTestFindSymbol_0100
 * @tc.desc: DynamicLoaderTest test for dynamic_find_symbol.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestFindSymbol_0100, TestSize.Level1)
{
    void* handle = DynamicLoadLibrary(nullptr, TEST_LIB, RTLD_LAZY);
    ASSERT_NE(handle, nullptr);

    void* symbol = DynamicFindSymbol(handle, TEST_SYMBOL);
    EXPECT_NE(symbol, nullptr);
    EXPECT_STREQ(DynamicGetError(), "");

    DynamicFreeLibrary(handle);
}

/**
 * @tc.name: DynamicLoaderTestFindSymbol_0200
 * @tc.desc: DynamicLoaderTest test for dynamic_find_symbol.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestFindSymbol_0200, TestSize.Level1)
{
    void* handle = DynamicLoadLibrary(nullptr, TEST_LIB, RTLD_LAZY);
    ASSERT_NE(handle, nullptr);

    void* symbol = DynamicFindSymbol(handle, "invalid_symbol");
    EXPECT_EQ(symbol, nullptr);
    
    DynamicFreeLibrary(handle);
}

/**
 * @tc.name: DynamicLoaderTestGetError_0100
 * @tc.desc: DynamicLoaderTest test for dynamic_get_error.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestGetError_0100, TestSize.Level1)
{
    void* handle = DynamicLoadLibrary(nullptr, "invalid_lib.so", RTLD_LAZY);
    EXPECT_EQ(handle, nullptr);

    const char* error = DynamicGetError();
    EXPECT_NE(error, nullptr);
    EXPECT_GT(std::strlen(error), 0);
}

/**
 * @tc.name: DynamicLoaderTestGetError_0200
 * @tc.desc: DynamicLoaderTest test for dynamic_get_error.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestGetError_0200, TestSize.Level1)
{
    void* handle = DynamicLoadLibrary(nullptr, TEST_LIB, RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    EXPECT_STREQ(DynamicGetError(), "");

    DynamicFreeLibrary(handle);
}

/**
 * @tc.name: DynamicLoaderTestFreeLibrary_0100
 * @tc.desc: DynamicLoaderTest test for DynamicFreeLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestFreeLibrary_0100, TestSize.Level1)
{
    void* handle = DynamicLoadLibrary(nullptr, TEST_LIB, RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    
    DynamicFreeLibrary(handle);
    
    void* newHandle = DynamicLoadLibrary(nullptr, TEST_LIB, RTLD_LAZY);
    EXPECT_NE(newHandle, nullptr);
    EXPECT_STREQ(DynamicGetError(), "");
    
    if (newHandle) {
        DynamicFreeLibrary(newHandle);
    }
}

/**
 * @tc.name: DynamicLoaderTestInitNamespace_0100
 * @tc.desc: DynamicLoaderTest test for dynamic_init_namespace.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestInitNamespace_0100, TestSize.Level1)
{
    Dl_namespace ns;
    const char* name = "test_namespace";

    DynamicInitNamespace(&ns, nullptr, TEST_LIB, name);
    EXPECT_STREQ(DynamicGetError(), "");
}

/**
 * @tc.name: DynamicLoaderTestInitNamespace_0200
 * @tc.desc: DynamicLoaderTest test for dynamic_init_namespace.
 * @tc.type: FUNC
 */
HWTEST_F(DynamicLoaderTest, DynamicLoaderTestInitNamespace_0200, TestSize.Level1)
{
    Dl_namespace ns;
    const char* name = "duplicate_namespace";

    DynamicInitNamespace(&ns, nullptr, TEST_LIB, name);
    EXPECT_STREQ(DynamicGetError(), "");

    DynamicInitNamespace(&ns, nullptr, TEST_LIB, name);
    EXPECT_STREQ(DynamicGetError(), "");
}
} // namespace EtsEnv
} // namespace OHOS