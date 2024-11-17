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

#include "app_scheduler.h"

#include "ability_manager_errors.h"

namespace OHOS {
namespace AAFwk {
int32_t AppScheduler::getBundleNameByPidResult = ERR_OK;
std::string AppScheduler::bundleNameValue;

AppScheduler::AppScheduler()
{}

AppScheduler::~AppScheduler()
{}

int32_t AppScheduler::GetBundleNameByPid(const int pid, std::string &bundleName, int32_t &uid)
{
    bundleName = bundleNameValue;
    return getBundleNameByPidResult;
}
} // namespace AAFwk
}  // namespace OHOS
