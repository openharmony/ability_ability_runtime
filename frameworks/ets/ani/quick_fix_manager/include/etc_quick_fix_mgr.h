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

#ifndef OHOS_ABILITY_RUNTIME_ETS_QUICK_FIX_MGR_H
#define OHOS_ABILITY_RUNTIME_ETS_QUICK_FIX_MGR_H

#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
namespace quickFixManager {
    static void applyQuickFixSync([[maybe_unused]]ani_env *env,
        ani_object aniHapModuleQuickFixFiles, ani_object callback);
    static void revokeQuickFixSync([[maybe_unused]]ani_env *env,
        ani_string aniBundleName, ani_object callback);
    static void getApplicationQuickFixInfoSync([[maybe_unused]]ani_env *env,
        ani_string aniBundleName, ani_object callback);
}
} // namespace quickFixManager
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_QUICK_FIX_MGR_H