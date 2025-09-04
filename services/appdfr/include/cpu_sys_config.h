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
#ifndef OHOS_ABILITY_RUNTIME_CPU_SYS_CONFIG_H
#define OHOS_ABILITY_RUNTIME_CPU_SYS_CONFIG_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
class CpuSysConfig {
public:
    CpuSysConfig();
    ~CpuSysConfig();

    static std::string GetFreqTimePath(int32_t cpu);
    static std::string GetMainThreadRunningTimePath(int32_t pid);
    static std::string GetProcRunningTimePath(int32_t pid);
    static std::string GetMaxCoreDimpsPath(int32_t maxCpuCount);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CPU_SYS_CONFIG_H
