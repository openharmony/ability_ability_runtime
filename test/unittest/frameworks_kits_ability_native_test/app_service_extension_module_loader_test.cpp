/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#define private public
#include "app_service_extension_module_loader.h"
#undef private
#include "runtime.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class AppServiceExtensionModuleLoaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppServiceExtensionModuleLoaderTest::SetUpTestCase(void)
{
}

void AppServiceExtensionModuleLoaderTest::TearDownTestCase(void)
{
}

void AppServiceExtensionModuleLoaderTest::SetUp(void)
{
}

void AppServiceExtensionModuleLoaderTest::TearDown(void)
{
}

/**
 * @tc.number: AppServiceExtensionModuleLoader_0100
 * @tc.name: OHOS_EXTENSION_GetExtensionModule
 * @tc.desc: Verify OHOS_EXTENSION_GetExtensionModule succeeded.
 */
HWTEST_F(AppServiceExtensionModuleLoaderTest, AppServiceExtensionModuleLoader_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppServiceExtensionModuleLoader_0100 start";
    void* handle = dlopen("/system/lib/extensionability/libservice_extension_module.z.so", RTLD_LAZY);
    if (handle != nullptr) {
        auto obj = reinterpret_cast<AbilityRuntime::AppServiceExtensionModuleLoader*>(
            dlsym(handle, "OHOS_EXTENSION_GetExtensionModule"));
        EXPECT_TRUE(obj != nullptr);
    }
    dlclose(handle);
    GTEST_LOG_(INFO) << "AppServiceExtensionModuleLoader_0100 end";
}

/**
 * @tc.number: AppServiceExtensionModuleLoader_0200
 * @tc.name: Create
 * @tc.desc: Verify Create succeeded.
 */
HWTEST_F(AppServiceExtensionModuleLoaderTest, AppServiceExtensionModuleLoader_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppServiceExtensionModuleLoader_0200 start";
    std::unique_ptr<AbilityRuntime::Runtime> runtime;
    auto extension = AbilityRuntime::AppServiceExtensionModuleLoader::GetInstance().Create(runtime);
    EXPECT_TRUE(extension != nullptr);
    GTEST_LOG_(INFO) << "AppServiceExtensionModuleLoader_0200 end";
}

/**
 * @tc.number: AppServiceExtensionModuleLoader_0300
 * @tc.name: GetParams
 * @tc.desc: Verify GetParams succeeded.
 */
HWTEST_F(AppServiceExtensionModuleLoaderTest, AppServiceExtensionModuleLoader_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AppServiceExtensionModuleLoader_0300 start";
    auto params = AbilityRuntime::AppServiceExtensionModuleLoader::GetInstance().GetParams();

    std::string key = "type";
    auto finder = params.find(key);
    if (finder != params.end()) {
        EXPECT_STREQ(finder->second.c_str(), "29");
    }

    key = "name";
    auto iter = params.find(key);
    if (iter != params.end()) {
        EXPECT_STREQ(iter->second.c_str(), "AppServiceExtension");
    }
    GTEST_LOG_(INFO) << "AppServiceExtensionModuleLoader_0300 end";
}
} // namespace AppExecFwk
} // namespace OHOS
