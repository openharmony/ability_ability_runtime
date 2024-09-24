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

#ifndef OHOS_ABILITY_RUNTIME_APPLICATION_UTIL_H
#define OHOS_ABILITY_RUNTIME_APPLICATION_UTIL_H

#include "common_event_manager.h"
#include "common_event_support.h"
#include "hilog_tag_wrapper.h"
#include "parameters.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
namespace ApplicationUtil {
using Want = OHOS::AAFwk::Want;
constexpr int32_t BOOT_COMPLETED_SIZE = 6;
constexpr const char* BOOTEVENT_BOOT_COMPLETED = "bootevent.boot.completed";
constexpr const char* ENABLE_APP_GALLERY_SELECTOR_UTIL = "abilitymanagerservice.support.appgallery.selector";

[[maybe_unused]] static void AppFwkBootEventCallback(const char *key, const char *value, void *context)
{
    if (strcmp(key, "bootevent.boot.completed") == 0 && strcmp(value, "true") == 0) {
        Want want;
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
        EventFwk::CommonEventData commonData {want};
        TAG_LOGI(AAFwkTag::ABILITYMGR, "init call, AppFwkBootEventCallback");
        EventFwk::CommonEventManager::PublishCommonEvent(commonData);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "init call, AppFwkBootEventCallback push BootEvent");
        return;
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "init call, AppFwkBootEventCallback key: %{public}s, value: %{public}s", key, value);
}

inline bool IsBootCompleted()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    std::string ret = OHOS::system::GetParameter(BOOTEVENT_BOOT_COMPLETED, "false");
    if (ret == "true") {
        return true;
    }
    return false;
}

inline bool IsEnableAppGallerySelector()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    std::string ret = OHOS::system::GetParameter(ENABLE_APP_GALLERY_SELECTOR_UTIL, "true");
    if (ret == "true") {
        return true;
    }
    return false;
}
}  // namespace ApplicationlUtil
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APPLICATION_UTIL_H
