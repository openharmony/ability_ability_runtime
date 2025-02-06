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

#include "multi_user_config_mgr.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t USER0 = 0;
    constexpr int32_t USER100 = 100;
}

MultiUserConfigurationMgr::MultiUserConfigurationMgr()
    : globalConfiguration_(std::make_shared<AppExecFwk::Configuration>())
{}

void MultiUserConfigurationMgr::InitConfiguration(std::shared_ptr<AppExecFwk::Configuration> config)
{
    std::lock_guard<std::mutex> guard(multiUserConfigurationMutex_);
    if (config == nullptr || globalConfiguration_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "config null");
        return;
    }
    std::vector<std::string> diffVe;
    config->CompareDifferent(diffVe, *globalConfiguration_);
    if (diffVe.size() != 0) {
        config->Merge(diffVe, *globalConfiguration_);
    }
    globalConfiguration_ = config;

    UpdateMultiUserConfigurationForGlobal(*globalConfiguration_);
}

std::shared_ptr<AppExecFwk::Configuration> MultiUserConfigurationMgr::GetConfigurationByUserId(const int32_t userId)
{
    std::lock_guard<std::mutex> guard(multiUserConfigurationMutex_);
    auto it = multiUserConfiguration_.find(userId);
    if (it != multiUserConfiguration_.end()) {
        return std::make_shared<AppExecFwk::Configuration>((it->second));
    } else {
        if (globalConfiguration_ == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "globalConfiguration_ null");
            return nullptr;
        }
        return std::make_shared<AppExecFwk::Configuration>(*globalConfiguration_);
    }
}

void MultiUserConfigurationMgr::HandleConfiguration(
    const int32_t userId, const Configuration& config, std::vector<std::string>& changeKeyV, bool &isNotifyUser0)
{
    std::lock_guard<std::mutex> guard(multiUserConfigurationMutex_);
    isNotifyUser0 = false;
    if (userId == -1) {
        if (globalConfiguration_ == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "globalConfiguration_ null");
            return;
        }
        {
            HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "globalConfiguration_->CompareDifferent");
            globalConfiguration_->CompareDifferent(changeKeyV, config);
        }
        if (changeKeyV.size() != 0) {
            HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "globalConfiguration_->Merge");
            globalConfiguration_->Merge(changeKeyV, config);
        }
        UpdateMultiUserConfiguration(config);
    } else {
        auto it = multiUserConfiguration_.find(userId);
        if (it != multiUserConfiguration_.end()) {
            it->second.CompareDifferent(changeKeyV, config);
            if (changeKeyV.size() != 0) {
                it->second.Merge(changeKeyV, config);
            }
        } else {
            if (globalConfiguration_ == nullptr) {
                TAG_LOGE(AAFwkTag::APPMGR, "globalConfiguration_ null");
                return;
            }
            Configuration userConfig = *globalConfiguration_;
            userConfig.CompareDifferent(changeKeyV, config);
            if (changeKeyV.size() != 0) {
                userConfig.Merge(changeKeyV, config);
            }
            multiUserConfiguration_[userId] = userConfig;
        }
        if (userId != USER0 && userId == MultiUserConfigurationMgr::GetForegroundOsAccountLocalId()) {
            std::vector<std::string> diff;
            multiUserConfiguration_[USER0].CompareDifferent(diff, multiUserConfiguration_[userId]);
            if (diff.size() != 0) {
                multiUserConfiguration_[USER0].Merge(diff, multiUserConfiguration_[userId]);
                isNotifyUser0 = true;
            }
        }
    }
}

void MultiUserConfigurationMgr::UpdateMultiUserConfiguration(const Configuration& config)
{
    for (auto& userConfig : multiUserConfiguration_) {
        std::vector<std::string> diffVe;
        userConfig.second.CompareDifferent(diffVe, config);
        if (diffVe.size() != 0) {
            userConfig.second.Merge(diffVe, config);
        }
    }
}

void MultiUserConfigurationMgr::UpdateMultiUserConfigurationForGlobal(const Configuration& globalConfig)
{
    for (auto& userConfig : multiUserConfiguration_) {
        Configuration globalCfg = globalConfig;
        std::vector<std::string> diffVe;
        globalCfg.CompareDifferent(diffVe, userConfig.second);
        if (diffVe.size() != 0) {
            globalCfg.Merge(diffVe, userConfig.second);
        }
        userConfig.second = globalCfg;
    }
}

int32_t MultiUserConfigurationMgr::GetForegroundOsAccountLocalId()
{
    int32_t foregroundUserId = USER100;
    auto errNo = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundUserId);
    if (errNo != 0) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetForegroundOsAccountLocalId failed: %{public}d", errNo);
        foregroundUserId = USER100;
    }
    return foregroundUserId;
}
} // namespace AppExecFwk
} // namespace OHOS
