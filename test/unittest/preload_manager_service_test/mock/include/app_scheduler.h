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

#ifndef OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H
#define OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H

#include <string>

#include "app_mgr_constants.h"
#include "singleton.h"

namespace OHOS {

namespace AAFwk {
class AppScheduler {
    DECLARE_DELAYED_SINGLETON(AppScheduler)
public:
    int32_t PreloadApplicationByPhase(const std::string &bundleName, int32_t userId, int32_t appIndex,
        AppExecFwk::PreloadPhase preloadPhase);

    int32_t CheckPreloadAppRecordExist(const std::string &bundleName, int32_t userId, int32_t appIndex,
        bool &isExist);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H
