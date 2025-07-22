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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_PERMISSION_UTIL_H
#define OHOS_ABILITY_RUNTIME_ABILITY_PERMISSION_UTIL_H

#include "nocopyable.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class AbilityPermissionUtil
 * provides ability permission utilities.
 */
class AbilityPermissionUtil {
public:
    /**
     * GetInstance, get an instance of AbilityPermissionUtil.
     *
     * @return An instance of AbilityPermissionUtil.
     */
    static AbilityPermissionUtil &GetInstance();

    bool IsStartSelfUIAbility();

private:
    /**
     * AbilityPermissionUtil, the private constructor.
     *
     */
    AbilityPermissionUtil() = default;

    /**
     * AbilityPermissionUtil, the private destructor.
     *
     */
    ~AbilityPermissionUtil() = default;

    DISALLOW_COPY_AND_MOVE(AbilityPermissionUtil);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ABILITY_PERMISSION_UTIL_H