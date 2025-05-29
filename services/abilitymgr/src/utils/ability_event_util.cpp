/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "ability_event_util.h"
#include "app_scheduler.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {

void AbilityEventUtil::HandleModuleInfoUpdated(const std::string &bundleName, const int uid,
    const std::string& moduleName, bool isPlugin)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "HandleModuleInfoUpdated start.");
    DelayedSingleton<AppScheduler>::GetInstance()->UpdateApplicationInfoInstalled(bundleName, uid, moduleName,
        isPlugin);
}

void AbilityEventUtil::SendStartAbilityErrorEvent(EventInfo &eventInfo, int32_t errCode, const std::string errMsg,
    bool isSystemError)
{
    if (taskHandler_ == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "task handler null");
        return;
    }
    EventName name = isSystemError ? EventName::START_ABILITY_SYSTEM_ERROR : EventName::START_ABILITY_ERROR;
    eventInfo.errCode = errCode;
    eventInfo.errMsg = errMsg;
    taskHandler_->SubmitTask([eventInfo, name]() {
        EventReport::SendAbilityEvent(name, HiSysEventType::FAULT, eventInfo);
        });
}
} // namespace AAFwk
} // namespace OHOS
