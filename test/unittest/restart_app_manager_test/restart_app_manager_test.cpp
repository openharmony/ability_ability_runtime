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

#define private public
#include "restart_app_manager.h"
#undef private

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AAFwk {
class RestartAppManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RestartAppManagerTest::SetUpTestCase(void)
{}
void RestartAppManagerTest::TearDownTestCase(void)
{}
void RestartAppManagerTest::TearDown(void)
{}
void RestartAppManagerTest::SetUp()
{}

/**
 * @tc.number: IsRestartAppFrequent_001
 * @tc.name: IsRestartAppFrequent
 * @tc.desc: Test whether IsRestartAppFrequent is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(RestartAppManagerTest, IsRestartAppFrequent_001, TestSize.Level1)
{
    RestartAppManager &instance = RestartAppManager::GetInstance();
    RestartAppKeyType key("", 123);
    time_t time = 0;
    instance.restartAppHistory_[key] = time;
    auto res = instance.IsRestartAppFrequent(key, time);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: IsRestartAppFrequent_002
 * @tc.name: IsRestartAppFrequent
 * @tc.desc: Test whether IsRestartAppFrequent is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(RestartAppManagerTest, IsRestartAppFrequent_002, TestSize.Level1)
{
    RestartAppManager &instance = RestartAppManager::GetInstance();
    RestartAppKeyType key("", 123);
    time_t time = 20;
    auto res = instance.IsRestartAppFrequent(key, time);
    EXPECT_EQ(res, false);
}
} // namespace AAFwk
} // namespace OHOS
