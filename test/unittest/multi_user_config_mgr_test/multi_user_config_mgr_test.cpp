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

#include <gtest/gtest.h>

#define private public
#include "multi_user_config_mgr.h"
#undef private
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {

class MultiUserConfigMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MultiUserConfigMgrTest::SetUpTestCase() {}
void MultiUserConfigMgrTest::TearDownTestCase() {}
void MultiUserConfigMgrTest::SetUp() {}
void MultiUserConfigMgrTest::TearDown() {}

/**
 * @tc.name: SetOrUpdateConfigByUserId_0100
 * @tc.desc: SetOrUpdateConfigByUserId.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, SetOrUpdateConfigByUserId_0100, TestSize.Level1)
{
    int32_t userId = 1;

    AppExecFwk::Configuration config1;
    int displayId = 1001;
    std::string val{ "中文" };
    config1.AddItem(displayId,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);

    AppExecFwk::Configuration config2;
    int displayId2 = 1002;
    std::string English{ "英文" };
    config2.AddItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, English);

    std::vector<std::string> changeKeyV;

    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();

    multiUserConfigurationMgr->multiUserConfiguration_.emplace(
        std::make_pair(userId, config2));
    multiUserConfigurationMgr->SetOrUpdateConfigByUserId(
        userId, config1, changeKeyV);
    EXPECT_FALSE(changeKeyV.empty());
    auto item = config2.GetItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    EXPECT_EQ(item, English);

    multiUserConfigurationMgr->multiUserConfiguration_.clear();
    changeKeyV.clear();
    multiUserConfigurationMgr->globalConfiguration_ = nullptr;
    multiUserConfigurationMgr->SetOrUpdateConfigByUserId(
        userId, config1, changeKeyV);

    multiUserConfigurationMgr->globalConfiguration_ =
        std::make_shared<AppExecFwk::Configuration>();
    multiUserConfigurationMgr->SetOrUpdateConfigByUserId(
        userId, config1, changeKeyV);
    EXPECT_FALSE(changeKeyV.empty());
    EXPECT_FALSE(multiUserConfigurationMgr->multiUserConfiguration_.empty());
}

/**
 * @tc.name: UpdateMultiUserConfiguration_0100
 * @tc.desc: UpdateMultiUserConfiguration.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, UpdateMultiUserConfiguration_0100, TestSize.Level1)
{
    AppExecFwk::Configuration config1;
    int displayId = 1001;
    std::string val{ "中文" };
    config1.AddItem(displayId,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);

    AppExecFwk::Configuration config2;
    int displayId2 = 1002;
    std::string English{ "英文" };
    config2.AddItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, English);

    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();
    multiUserConfigurationMgr->multiUserConfiguration_.emplace(
        std::make_pair(1, config2));
    multiUserConfigurationMgr->UpdateMultiUserConfiguration(config1);
    for (auto& item : multiUserConfigurationMgr->multiUserConfiguration_) {
        auto result = item.second.GetItem(displayId2,
            AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
        EXPECT_EQ(result, English);
    }
}

/**
 * @tc.name: UpdateMultiUserConfigurationForGlobal_0100
 * @tc.desc: UpdateMultiUserConfigurationForGlobal.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, UpdateMultiUserConfigurationForGlobal_0100, TestSize.Level1)
{
    AppExecFwk::Configuration globalConfig;
    int displayId = 1001;
    std::string val{ "中文" };
    globalConfig.AddItem(displayId,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);

    AppExecFwk::Configuration config;
    int displayId2 = 1002;
    std::string English{ "英文" };
    config.AddItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, English);

    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();

    multiUserConfigurationMgr->multiUserConfiguration_.emplace(
        std::make_pair(1, config));
    multiUserConfigurationMgr->UpdateMultiUserConfiguration(globalConfig);

    for (auto& item : multiUserConfigurationMgr->multiUserConfiguration_) {
        auto result = item.second.GetItem(displayId,
            AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
        EXPECT_EQ(result, val);
    }
}

/**
 * @tc.name: GetForegroundOsAccountLocalId_0100
 * @tc.desc: GetForegroundOsAccountLocalId.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, GetForegroundOsAccountLocalId_0100, TestSize.Level1)
{
    EXPECT_EQ(AppExecFwk::MultiUserConfigurationMgr::
        GetForegroundOsAccountLocalId(), 100);
}

/**
 * @tc.name: HandleConfiguration_0100
 * @tc.desc: HandleConfiguration.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, HandleConfiguration_0100, TestSize.Level1)
{
    AppExecFwk::Configuration config1;
    int displayId = 1001;
    std::string val{ "中文" };
    config1.AddItem(displayId,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);

    int32_t userId = -1;
    std::vector<std::string> changeKeyV;
    bool isNotifyUser0 = true;

    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();
    multiUserConfigurationMgr->globalConfiguration_ = nullptr;
    multiUserConfigurationMgr->HandleConfiguration(userId,
        config1, changeKeyV, isNotifyUser0);

    multiUserConfigurationMgr->globalConfiguration_ =
        std::make_shared<AppExecFwk::Configuration>();
    int displayId2 = 1002;
    std::string English{ "英文" };
    multiUserConfigurationMgr->globalConfiguration_->AddItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, English);

    multiUserConfigurationMgr->HandleConfiguration(userId,
        config1, changeKeyV, isNotifyUser0);
    EXPECT_FALSE(changeKeyV.empty());
    EXPECT_EQ(multiUserConfigurationMgr->globalConfiguration_->GetItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE), English);
}

/**
 * @tc.name: HandleConfiguration_0200
 * @tc.desc: HandleConfiguration.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, HandleConfiguration_0200, TestSize.Level1)
{
    int32_t userId =
        AppExecFwk::MultiUserConfigurationMgr::GetForegroundOsAccountLocalId();
    AppExecFwk::Configuration config1;
    int displayId = 1001;
    std::string val{ "中文" };
    config1.AddItem(displayId,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);

    AppExecFwk::Configuration config2;
    int displayId2 = 1002;
    std::string English{ "英文" };
    config2.AddItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, English);

    std::vector<std::string> changeKeyV;
    bool isNotifyUser0 = false;
    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();
    multiUserConfigurationMgr->multiUserConfiguration_.emplace(
        std::make_pair(userId, config2));
    multiUserConfigurationMgr->HandleConfiguration(userId,
        config1, changeKeyV, isNotifyUser0);
    EXPECT_FALSE(changeKeyV.empty());
    EXPECT_EQ(isNotifyUser0, true);
}

/**
 * @tc.name: InitConfiguration_0200
 * @tc.desc: InitConfiguration.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, InitConfiguration_0100, TestSize.Level1)
{
    auto config = std::make_shared<AppExecFwk::Configuration>();
    int displayId = 1001;
    std::string val{ "中文" };
    config->AddItem(displayId, AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);
    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();
    multiUserConfigurationMgr->globalConfiguration_ = nullptr;
    multiUserConfigurationMgr->InitConfiguration(config);

    multiUserConfigurationMgr->globalConfiguration_ =
        std::make_shared<AppExecFwk::Configuration>();
    int displayId2 = 1002;
    std::string English{ "英文" };
    multiUserConfigurationMgr->globalConfiguration_->AddItem(displayId2,
        AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, English);
    multiUserConfigurationMgr->InitConfiguration(config);
    EXPECT_EQ(config, multiUserConfigurationMgr->globalConfiguration_);
}

/**
 * @tc.name: GetConfigurationByUserId_0200
 * @tc.desc: GetConfigurationByUserId.
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserConfigMgrTest, GetConfigurationByUserId_0100, TestSize.Level1)
{
    int32_t userId = 1;
    auto multiUserConfigurationMgr =
        std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();

    AppExecFwk::Configuration config;
    int displayId = 1001;
    std::string val{ "中文" };
    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, val);
    multiUserConfigurationMgr->multiUserConfiguration_.emplace(std::make_pair(userId, config));
    EXPECT_NE(multiUserConfigurationMgr->GetConfigurationByUserId(userId), nullptr);

    multiUserConfigurationMgr->multiUserConfiguration_.clear();
    multiUserConfigurationMgr->globalConfiguration_ = nullptr;
    EXPECT_EQ(multiUserConfigurationMgr->GetConfigurationByUserId(userId), nullptr);

    multiUserConfigurationMgr->globalConfiguration_ =
        std::make_shared<AppExecFwk::Configuration>();
    EXPECT_NE(multiUserConfigurationMgr->GetConfigurationByUserId(userId), nullptr);
}

} // namespace AppExecFwk
} // namespace OHOS