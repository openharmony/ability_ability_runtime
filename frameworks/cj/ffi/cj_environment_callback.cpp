/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cj_environment_callback.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
CjEnvironmentCallback::CjEnvironmentCallback()
{
}

int32_t CjEnvironmentCallback::serialNumber_ = 0;

int32_t ConvertColorMode(std::string colormode)
{
    auto resolution = -1;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "dark", 0 },
        { "light", 1 },
    };
    for (const auto& [tempColorMode, value] : resolutions) {
        if (tempColorMode == colormode) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

int32_t ConvertDirection(std::string direction)
{
    auto resolution = -1;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "vertical", 0 },
        { "horizontal", 1 },
    };
    for (const auto& [tempDirection, value] : resolutions) {
        if (tempDirection == direction) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

int32_t ConvertDensity(std::string density)
{
    auto resolution = 0;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "sdpi", 120 },
        { "mdpi", 160 },
        { "ldpi", 240 },
        { "xldpi", 320 },
        { "xxldpi", 480 },
        { "xxxldpi", 640 },
    };
    for (const auto& [tempdensity, value] : resolutions) {
        if (tempdensity == density) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

int32_t ConvertDisplayId(std::string displayId)
{
    if (displayId == AppExecFwk::ConfigurationInner::EMPTY_STRING) {
        return -1;
    }
    return std::stoi(displayId);
}

CConfiguration CreateCConfiguration(const AppExecFwk::Configuration &configuration)
{
    CConfiguration cfg;
    cfg.language = CreateCStringFromString(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE));
    cfg.colorMode = ConvertColorMode(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE));
    std::string direction = configuration.GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DIRECTION);
    cfg.direction = ConvertDirection(direction);
    std::string density = configuration.GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DENSITYDPI);
    cfg.screenDensity = ConvertDensity(density);
    cfg.displayId = ConvertDisplayId(configuration.GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DISPLAYID));
    std::string hasPointerDevice = configuration.GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    cfg.hasPointerDevice = hasPointerDevice == "true" ? true : false;
    std::string fontSizeScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    cfg.fontSizeScale = fontSizeScale == "" ? 1.0 : std::stod(fontSizeScale);
    std::string fontWeightScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
    cfg.fontWeightScale = fontWeightScale == "" ? 1.0 : std::stod(fontWeightScale);
    cfg.mcc = CreateCStringFromString(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC));
    cfg.mnc = CreateCStringFromString(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC));
    return cfg;
}

void CjEnvironmentCallback::CallConfigurationUpdatedInner(const AppExecFwk::Configuration &config,
    const std::map<int32_t, std::function<void(CConfiguration)>> &callbacks)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = onConfiguration");
    for (auto &callback : callbacks) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, " Invalid cjCallback");
            return;
        }
        auto cfg = CreateCConfiguration(config);
        callback.second(cfg);
    }
}

void CjEnvironmentCallback::OnConfigurationUpdated(const AppExecFwk::Configuration &config)
{
    std::weak_ptr<CjEnvironmentCallback> thisWeakPtr(shared_from_this());
    std::shared_ptr<CjEnvironmentCallback> cjEnvCallback = thisWeakPtr.lock();
    if (cjEnvCallback) {
        cjEnvCallback->CallConfigurationUpdatedInner(config, onConfigurationUpdatedCallbacks_);
    }
}

void CjEnvironmentCallback::CallMemoryLevelInner(const int level,
    const std::map<int32_t, std::function<void(int32_t)>> &callbacks)
{
    TAG_LOGD(AAFwkTag::APPKIT, "onMemoryLevel");
    for (auto &callback : callbacks) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid jsCallback");
            return;
        }
        callback.second(static_cast<int32_t>(level));
    }
}

void CjEnvironmentCallback::OnMemoryLevel(const int level)
{
    std::weak_ptr<CjEnvironmentCallback> thisWeakPtr(shared_from_this());
    std::shared_ptr<CjEnvironmentCallback> cjEnvCallback = thisWeakPtr.lock();
    if (cjEnvCallback) {
        cjEnvCallback->CallMemoryLevelInner(level, onMemoryLevelCallbacks_);
    }
}

int32_t CjEnvironmentCallback::Register(std::function<void(CConfiguration)> cfgCallback,
    std::function<void(int32_t)> memCallback, bool isSync)
{
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    if (isSync) {
        return -1;
    } else {
        onConfigurationUpdatedCallbacks_.emplace(callbackId, cfgCallback);
        onMemoryLevelCallbacks_.emplace(callbackId, memCallback);
    }
    return callbackId;
}

bool CjEnvironmentCallback::UnRegister(int32_t callbackId, bool isSync)
{
    TAG_LOGD(AAFwkTag::APPKIT, "callbackId : %{public}d", callbackId);
    if (isSync) {
        return false;
    }
    auto itCfg = onConfigurationUpdatedCallbacks_.find(callbackId);
    if (itCfg == onConfigurationUpdatedCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d is not in callbacks_", callbackId);
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId : %{public}d", itCfg->first);
    auto itMem = onMemoryLevelCallbacks_.find(callbackId);
    if (itMem == onMemoryLevelCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d is not in callbacks_", callbackId);
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId : %{public}d", itMem->first);
    return onConfigurationUpdatedCallbacks_.erase(callbackId) == 1 && onMemoryLevelCallbacks_.erase(callbackId) == 1;
}

bool CjEnvironmentCallback::IsEmpty() const
{
    return onConfigurationUpdatedCallbacks_.empty() && onMemoryLevelCallbacks_.empty();
}
}  // namespace AbilityRuntime
}  // namespace OHOS