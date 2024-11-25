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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_KEEP_ALIVE_DATA_MANAGER_H
#define OHOS_ABILITY_RUNTIME_ABILITY_KEEP_ALIVE_DATA_MANAGER_H

#include <vector>

#include "keep_alive_info.h"

namespace OHOS {
namespace AbilityRuntime {
class AbilityKeepAliveDataManager {
public:
    static AbilityKeepAliveDataManager &GetInstance();

    int32_t InsertKeepAliveData(const KeepAliveInfo &info);

    int32_t DeleteKeepAliveData(const KeepAliveInfo &info);

    KeepAliveStatus QueryKeepAliveData(const KeepAliveInfo &info);

    int32_t QueryKeepAliveApplications(const KeepAliveInfo &queryParam, std::vector<KeepAliveInfo> &infoList);

public:
    static int32_t callSetResult;
    static int32_t callInsertResult;
    static int32_t callDeleteResult;
    static int32_t callQueryDataResult;
    static int32_t callQueryApplicationResult;
    static KeepAliveSetter queryDataSetter;
    static std::vector<KeepAliveInfo> returnInfoList;

private:
    AbilityKeepAliveDataManager();
    ~AbilityKeepAliveDataManager();
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ABILITY_KEEP_ALIVE_DATA_MANAGER_H