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

#include "app_scheduler.h"

#include "mock_my_status.h"

namespace OHOS {
namespace AAFwk {
AppScheduler::AppScheduler()
{}

AppScheduler::~AppScheduler()
{}

int32_t AppScheduler::PreloadApplicationByPhase(const std::string &bundleName, int32_t userId, int32_t appIndex,
    AppExecFwk::PreloadPhase preloadPhase)
{
    return MyStatus::GetInstance().retPreloadApplicationByPhase_;
}

int32_t AppScheduler::CheckPreloadAppRecordExist(const std::string &bundleName, int32_t userId, int32_t appIndex,
    bool &isExist)
{
    isExist = AAFwk::MyStatus::GetInstance().isPreloadApplicationRecordExist_;
    return MyStatus::GetInstance().retCheckPreloadAppRecordExist_;
}
}  // namespace AAFwk
}  // namespace OHOS
