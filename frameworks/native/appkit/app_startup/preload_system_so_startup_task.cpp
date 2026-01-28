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

#include "preload_system_so_startup_task.h"

#include "event_report.h"
#include "hilog_tag_wrapper.h"
#include "native_module_manager.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr char OHM_URL_OHOS_PREFIX[] = "@ohos:";
constexpr char OHM_URL_APP_COLON_TAG = ':';

bool StringStartWith(const std::string& str, const std::string& startStr)
{
    size_t startStrLen = startStr.length();
    return ((str.length() > startStrLen) && (str.compare(0, startStrLen, startStr) == 0));
}

int32_t ParseSystemSoOhmUrl(const std::string& ohmUrl, std::string& soName)
{
    // @ohos:<moduleName>
    size_t pos = ohmUrl.find(OHM_URL_APP_COLON_TAG);
    if (pos == std::string::npos) {
        TAG_LOGE(AAFwkTag::STARTUP, "invalid app ohmUrl: %{public}s", ohmUrl.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }
    soName = ohmUrl.substr(pos + 1);

    return ERR_OK;
}

int32_t ParseOhmUrl(const std::string& ohmUrl, std::string& soName)
{
    if (ohmUrl.empty()) {
        TAG_LOGE(AAFwkTag::STARTUP, "ohmUrl is empty");
        return ERR_STARTUP_INVALID_VALUE;
    }

    if (!StringStartWith(ohmUrl, OHM_URL_OHOS_PREFIX)) {
        TAG_LOGE(AAFwkTag::STARTUP, "invalid ohmUrl: %{public}s", ohmUrl.c_str());
        return ERR_STARTUP_INVALID_VALUE;
    }

    return ParseSystemSoOhmUrl(ohmUrl, soName);
}
} // namespace
const std::string PreloadSystemSoStartupTask::TASK_TYPE = "PreloadSystemSo";

PreloadSystemSoStartupTask::PreloadSystemSoStartupTask(const std::string& name, const std::string& ohmUrl)
    : PreloadSoStartupTask(name, ohmUrl)
{
    SetWaitOnMainThread(false);
    SetCallCreateOnMainThread(false);
}

PreloadSystemSoStartupTask::~PreloadSystemSoStartupTask() = default;

const std::string &PreloadSystemSoStartupTask::GetType() const
{
    return TASK_TYPE;
}

int32_t PreloadSystemSoStartupTask::RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback)
{
    std::string soName;
    int32_t code = ParseOhmUrl(ohmUrl_, soName);
    AAFwk::EventInfo eventInfo;
    if (code != ERR_OK) {
        TAG_LOGW(AAFwkTag::STARTUP,
            "task %{public}s, parse ohmUrl failed: %{public}s", name_.c_str(), ohmUrl_.c_str());
        return ERR_OK;
    }
    TAG_LOGD(AAFwkTag::STARTUP, "task: %{public}s, soName: %{public}s", name_.c_str(), soName.c_str());

    NativeModuleManager* moduleManager = NativeModuleManager::GetInstance();
    if (moduleManager == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "moduleManager is null");
        OnCompletedCallback::OnCallback(std::move(callback), ERR_STARTUP_INTERNAL_ERROR);
        eventInfo.errCode = ERR_NATIVE_MODULE_MANAGER_CONSTRUCTION;
        eventInfo.errReason = "moduleManager is null";
        AAFwk::EventReport::SendLaunchFrameworkEvent(
            AAFwk::EventName::STARTUP_TASK_ERROR, HISYSEVENT_FAULT, eventInfo);
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    std::string errInfo;
    NativeModule* module = moduleManager->LoadNativeModule(soName.c_str(), nullptr, false, errInfo, false, "");
    if (module == nullptr) {
        TAG_LOGW(AAFwkTag::STARTUP, "module is null, errInfo: %{public}s", errInfo.c_str());
        OnCompletedCallback::OnCallback(std::move(callback), ERR_OK);
        eventInfo.errCode = ERR_LOAD_NATIVE_MODULE;
        eventInfo.errReason = errInfo;
        AAFwk::EventReport::SendLaunchFrameworkEvent(
            AAFwk::EventName::STARTUP_TASK_ERROR, HISYSEVENT_FAULT, eventInfo);
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    OnCompletedCallback::OnCallback(std::move(callback), ERR_OK);
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS
