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
#ifndef OHOS_ABILITY_RUNTIME_STS_APP_MANAGER_UTILS_H
#define OHOS_ABILITY_RUNTIME_STS_APP_MANAGER_UTILS_H

#include "sts_runtime.h"
#include <vector>
#include "running_process_info.h"
#include "app_state_data.h"
#include "running_multi_info.h"
#include "process_data.h"

namespace OHOS {
namespace AppManagerSts {
ani_object NewArrayClass(ani_env *env, const std::vector<std::string>& data);
ani_object WrapAppStateData(ani_env *env, const AppExecFwk::AppStateData &appStateData);
void SetAppStateData(ani_env *env, ani_object object, const AppExecFwk::AppStateData &appStateData);
void SetProcessInformation(ani_env *env, ani_object object, const AppExecFwk::RunningProcessInfo &processInfo);
ani_object WrapProcessInformation(ani_env *env, const AppExecFwk::RunningProcessInfo &processInfo);
ani_object CreateRunningProcessInfoArray (ani_env *env, std::vector<AppExecFwk::RunningProcessInfo> infos);
ani_object CreateAppStateDataArray (ani_env *env, std::vector<AppExecFwk::AppStateData> data);
ani_object CreateRunningMultiInstanceInfoArray(ani_env *env,
    std::vector<AppExecFwk::RunningMultiInstanceInfo> infos);
ani_object CreateRunningAppCloneArray(ani_env *env, std::vector<AppExecFwk::RunningAppClone> infos);
void SetRunningMultiAppInfo(ani_env *env, ani_object object,
    const AppExecFwk::RunningMultiAppInfo &runningMultiAppInfo);
ani_object WrapRunningMultiAppInfo(ani_env *env, const AppExecFwk::RunningMultiAppInfo &runningMultiAppInfo);
ani_object WrapRunningMultiInstanceInfo(ani_env *env, const AppExecFwk::RunningMultiInstanceInfo &instanceInfo);
void SetRunningMultiInstanceInfo(ani_env *env, ani_object object,
    const AppExecFwk::RunningMultiInstanceInfo &instanceInfo);
ani_object WrapRunningAppClone(ani_env *env, const AppExecFwk::RunningAppClone &runningAppClone);
void SetRunningAppClone(ani_env *env, ani_object object, const AppExecFwk::RunningAppClone &runningAppClone);
ani_object WrapProcessData(ani_env *env, const AppExecFwk::ProcessData &processData);
void SetProcessData(ani_env* env, ani_object object, const AppExecFwk::ProcessData &processData);
bool UnWrapArrayString(ani_env *env, ani_object arrayObj, std::vector<std::string> stringList);

} // namespace AppManagerSts
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_APP_MANAGER_UTILS_H
