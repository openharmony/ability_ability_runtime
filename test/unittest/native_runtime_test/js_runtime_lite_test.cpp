/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_environment.h"
#include "js_runtime_lite.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {

class JsRuntimeLiteTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void JsRuntimeLiteTest::SetUpTestCase() {}

void JsRuntimeLiteTest::TearDownTestCase() {}

void JsRuntimeLiteTest::SetUp() {}

void JsRuntimeLiteTest::TearDown() {}

/**
 * @tc.name: JsRuntimeLiteTest_001
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsRuntimeLiteTest, JsRuntimeLiteTest_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "JsRuntimeLiteTest_001 start");
    Options options;
    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
    auto err = JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv);
    EXPECT_EQ(err, napi_status::napi_ok);

    err = JsRuntimeLite::GetInstance().RemoveJsEnv(reinterpret_cast<napi_env>(jsEnv->GetNativeEngine()));
    EXPECT_EQ(err, napi_status::napi_ok);
    TAG_LOGI(AAFwkTag::TEST, "JsRuntimeLiteTest_001 end");
}

/**
 * @tc.name: JsRuntimeLiteTest_002
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsRuntimeLiteTest, JsRuntimeLiteTest_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "JsRuntimeLiteTest_002 start");
    Options options;
    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
    auto err = JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv);
    EXPECT_EQ(err, napi_status::napi_ok);

    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv2 = nullptr;
    err = JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv2);
    EXPECT_EQ(err, napi_status::napi_create_ark_runtime_only_one_env_per_thread);

    err = JsRuntimeLite::GetInstance().RemoveJsEnv(reinterpret_cast<napi_env>(jsEnv->GetNativeEngine()));
    EXPECT_EQ(err, napi_status::napi_ok);

    err = JsRuntimeLite::GetInstance().RemoveJsEnv(reinterpret_cast<napi_env>(jsEnv2->GetNativeEngine()));
    EXPECT_EQ(err, napi_status::napi_destroy_ark_runtime_env_not_exist);
    TAG_LOGI(AAFwkTag::TEST, "JsRuntimeLiteTest_002 end");
}

/**
 * @tc.name: JsRuntimeLiteTest_003
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(JsRuntimeLiteTest, JsRuntimeLiteTest_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "JsRuntimeLiteTest_003 start");
    Options options;
    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
    auto err = JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv);
    EXPECT_EQ(err, napi_status::napi_ok);

    napi_env env = reinterpret_cast<napi_env>(jsEnv->GetNativeEngine());
    err = JsRuntimeLite::GetInstance().Init(options, env);
    EXPECT_EQ(err, napi_status::napi_ok);

    err = JsRuntimeLite::GetInstance().RemoveJsEnv(env);
    EXPECT_EQ(err, napi_status::napi_ok);
    TAG_LOGI(AAFwkTag::TEST, "JsRuntimeLiteTest_003 end");
}

/**
 * @tc.name: GetChildOptions_0100
 * @tc.desc: JsRuntime test for GetChildOptions.
 * @tc.type: FUNC
 */
HWTEST_F(JsRuntimeLiteTest, GetChildOptions_0100, TestSize.Level1)
{
    auto child = JsRuntimeLite::GetInstance().GetChildOptions();
    EXPECT_TRUE(child == nullptr);
}

/**
 * @tc.name: GetPkgContextInfoListMap_0100
 * @tc.desc: JsRuntimeLiteTest test for GetPkgContextInfoListMap.
 * @tc.type: FUNC
 */
HWTEST_F(JsRuntimeLiteTest, GetPkgContextInfoListMap_0100, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetPkgContextInfoListMap_0100 start");

    std::map<std::string, std::string> modulePkgContentMap;
    std::string pkgContentJsonString = R"({"library":{"packageName":"library","bundleName":"com.xxx.xxxx","moduleName":
                "library","version":"1.0.0","entryPath":"","isSO":false}})";
    modulePkgContentMap["entry"] = pkgContentJsonString;

    AbilityRuntime::Runtime::Options options;
    options.preload = true;
    auto jsRuntime = AbilityRuntime::JsRuntime::Create(options);
    std::map<std::string, std::vector<std::vector<std::string>>> ret;
    std::map<std::string, std::string> pkgAliasMap;
    JsRuntimeLite::GetInstance().GetPkgContextInfoListMap(modulePkgContentMap, ret, pkgAliasMap);
    std::string expectString = "library:packageName:library:bundleName:";
    expectString += "com.xxx.xxxx:moduleName:library:version:1.0.0:entryPath::isSO:false:";
    auto it = ret.find("entry");
    ASSERT_EQ(it, ret.end());
    std::string pkgRetString;
    for (const auto& vec : it->second) {
    for (const auto& str : vec) {
    pkgRetString += str + ":";
    }
    }
    ASSERT_EQ(pkgRetString, "");
    TAG_LOGI(AAFwkTag::TEST, "GetPkgContextInfoListMap_0100 end");
}

/**
 * @tc.name: GetPkgContextInfoListMap_0200
 * @tc.desc: JsRuntimeLiteTest test for GetPkgContextInfoListMap.
 * @tc.type: FUNC
 */
HWTEST_F(JsRuntimeLiteTest, GetPkgContextInfoListMap_0200, TestSize.Level0)
{
    TAG_LOGI(AAFwkTag::TEST, "GetPkgContextInfoListMap_0200 start");

    std::map<std::string, std::string> modulePkgContentMap;
    std::string pkgContentJsonString = R"({"library":{"packageName":"library","bundleName":"com.xxx.xxxx","moduleName":
                "library","version":"1.0.0","entryPath":"","isSO":false}})";
    modulePkgContentMap["entry"] = pkgContentJsonString;

    std::string libraryString = R"({"library":{"packageName":"library","bundleName":"com.xxx.xxxx","moduleName":
                "library","version":"1.0.0","entryPath":"","isSO":false}})";
    modulePkgContentMap["library"] = libraryString;

    AbilityRuntime::Runtime::Options options;
    options.preload = true;
    auto jsRuntime = AbilityRuntime::JsRuntime::Create(options);
    std::map<std::string, std::vector<std::vector<std::string>>> ret;
    std::map<std::string, std::string> pkgAliasMap;
    JsRuntimeLite::GetInstance().GetPkgContextInfoListMap(modulePkgContentMap, ret, pkgAliasMap);
    std::string expectString = "library:packageName:library:bundleName:";
    expectString += "com.xxx.xxxx:moduleName:library:version:1.0.0:entryPath::isSO:false:";
    auto it = ret.find("entry");
    ASSERT_EQ(it, ret.end());
    auto libraryIt = ret.find("library");
    ASSERT_EQ(libraryIt, ret.end());
    std::string pkgRetString;
    for (const auto& vec : it->second) {
    for (const auto& str : vec) {
    pkgRetString += str + ":";
    }
    }
    ASSERT_EQ(pkgRetString, "");
    TAG_LOGI(AAFwkTag::TEST, "GetPkgContextInfoListMap_0200 end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS