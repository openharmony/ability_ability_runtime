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

#ifndef OHOS_ABILITY_RUNTIME_RDB_ABILITY_RESIDENT_PROCESS_RDB_H
#define OHOS_ABILITY_RUNTIME_RDB_ABILITY_RESIDENT_PROCESS_RDB_H

#include <string>

namespace OHOS {
namespace AbilityRuntime {
class AmsResidentProcessRdb final {
public:
    static int32_t retGetResidentProcessEnable;
    static bool residentProcessEnable;

public:
    static AmsResidentProcessRdb &GetInstance()
    {
        static AmsResidentProcessRdb instance;
        return instance;
    }

    int32_t GetResidentProcessEnable(const std::string &bundleName, bool &enable)
    {
        enable = residentProcessEnable;
        return retGetResidentProcessEnable;
    }

private:
    AmsResidentProcessRdb() {}
    ~AmsResidentProcessRdb() {}
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_RDB_ABILITY_RESIDENT_PROCESS_RDB_H