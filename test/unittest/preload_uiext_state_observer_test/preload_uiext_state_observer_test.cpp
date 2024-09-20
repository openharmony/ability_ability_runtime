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

#include "ability_handler.h"
#define private public
#include "preload_uiext_state_observer.h"
#undef private
#include "ability_record.h"
#include "extension_record.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace testing::ext;
using namespace AAFwk;
using namespace AbilityRuntime;

class PreloadUIextStateObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreloadUIextStateObserverTest::SetUpTestCase(void)
{}

void PreloadUIextStateObserverTest::TearDownTestCase(void)
{}

void PreloadUIextStateObserverTest::SetUp(void)
{}

void PreloadUIextStateObserverTest::TearDown(void)
{}

/**
 * @tc.number: OnProcessDied_001
 * @tc.name: OnProcessDied
 * @tc.desc: Test whether OnProcessDied is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(PreloadUIextStateObserverTest, OnProcessDied_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "OnProcessDied_001 start";
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord =
        std::make_shared<AAFwk::AbilityRecord>(want, abilityInfo, applicationInfo);
    auto extensionRecordSharedPtr = std::make_shared<AbilityRuntime::ExtensionRecord>(abilityRecord);
    auto hostPid = extensionRecordSharedPtr->hostPid_ = 10;
    std::weak_ptr<AbilityRuntime::ExtensionRecord> extensionRecord = extensionRecordSharedPtr;
    PreLoadUIExtStateObserver preLoadUIExtStateObserver(extensionRecord);
    AppExecFwk::ProcessData processData;
    int32_t diedPid = processData.pid;
    preLoadUIExtStateObserver.OnProcessDied(processData);
    auto record = preLoadUIExtStateObserver.extensionRecord_.lock();
    EXPECT_TRUE(record != nullptr);
    EXPECT_TRUE(record->hostPid_ != diedPid);
    GTEST_LOG_(INFO) << "OnProcessDied_001 end";
}

/**
 * @tc.number: OnProcessDied_002
 * @tc.name: OnProcessDied
 * @tc.desc: Test whether OnProcessDied is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(PreloadUIextStateObserverTest, OnProcessDied_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "OnProcessDied_002 start";
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord =
        std::make_shared<AAFwk::AbilityRecord>(want, abilityInfo, applicationInfo);
    auto extensionRecordSharedPtr = std::make_shared<AbilityRuntime::ExtensionRecord>(abilityRecord);
    std::weak_ptr<AbilityRuntime::ExtensionRecord> extensionRecord = extensionRecordSharedPtr;
    PreLoadUIExtStateObserver preLoadUIExtStateObserver(extensionRecord);
    AppExecFwk::ProcessData processData;
    int32_t diedPid = processData.pid;
    preLoadUIExtStateObserver.OnProcessDied(processData);
    auto record = preLoadUIExtStateObserver.extensionRecord_.lock();
    EXPECT_TRUE(record != nullptr);
    EXPECT_TRUE(record->hostPid_ == diedPid);
    GTEST_LOG_(INFO) << "OnProcessDied_002 end";
}

/**
 * @tc.number: OnProcessDied_003
 * @tc.name: OnProcessDied
 * @tc.desc: Test whether OnProcessDied is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(PreloadUIextStateObserverTest, OnProcessDied_003, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "OnProcessDied_003 start";
    std::weak_ptr<AbilityRuntime::ExtensionRecord> extensionRecord;
    PreLoadUIExtStateObserver preLoadUIExtStateObserver(extensionRecord);
    AppExecFwk::ProcessData processData;
    preLoadUIExtStateObserver.OnProcessDied(processData);
    auto record = preLoadUIExtStateObserver.extensionRecord_.lock();
    EXPECT_TRUE(record == nullptr);
    GTEST_LOG_(INFO) << "OnProcessDied_003 end";
}
} // namespace AbilityRuntime
} // namespace OHOS
