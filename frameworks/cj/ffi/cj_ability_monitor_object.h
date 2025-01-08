/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_MONITOR_OBJECT_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_MONITOR_OBJECT_H

#include <cstdint>
#include <memory>
#include <string>

#include "cj_macro.h"

extern "C" {
struct CJMonitorFuncs {
    void (*cjOnAbilityCreate)(int64_t monitorId, int64_t abilityId);
    void (*cjOnAbilityForeground)(int64_t monitorId, int64_t abilityId);
    void (*cjOnAbilityBackground)(int64_t monitorId, int64_t abilityId);
    void (*cjOnAbilityDestroy)(int64_t monitorId, int64_t abilityId);
    void (*cjOnWindowStageCreate)(int64_t monitorId, int64_t abilityId);
    void (*cjOnWindowStageRestore)(int64_t monitorId, int64_t abilityId);
    void (*cjOnWindowStageDestroy)(int64_t monitorId, int64_t abilityId);
};

CJ_EXPORT void RegisterCJMonitorFuncs(void (*registerFunc)(CJMonitorFuncs*));
}
namespace OHOS {
namespace AbilityDelegatorCJ {
class CJMonitorObject {
public:
    /**
     * A constructor used to create a CJMonitorObject instance with the input
     * parameter passed.
     */
    explicit CJMonitorObject(const int64_t monitorId);
    /**
     * Default deconstructor used to deconstruct.
     */
    ~CJMonitorObject() = default;

    /**
     * Called when ability is started.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityCreate(const int64_t abilityId);

    /**
     * Called when ability is in foreground.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityForeground(const int64_t abilityId);

    /**
     * Called when ability is in background.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityBackground(const int64_t abilityId);

    /**
     * Called when ability is stopped.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnAbilityDestroy(const int64_t abilityId);

    /**
     * Called when window stage is created.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnWindowStageCreate(const int64_t abilityId);

    /**
     * Called when window stage is restored.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnWindowStageRestore(const int64_t abilityId);

    /**
     * Called when window stage is destroyed.
     * Then call the corresponding method on the js side through the saved js
     * object.
     *
     * @param abilityId Indicates the ability object.
     */
    void OnWindowStageDestroy(const int64_t abilityId);

    int64_t GetId()
    {
        return monitorId_;
    }

private:
    int64_t monitorId_;
};
} // namespace AbilityDelegatorCJ
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_ABILITY_MONITOR_H