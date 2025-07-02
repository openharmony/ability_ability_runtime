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
 
#ifndef OHOS_ABILITY_RUNTIME_EVENT_HUB_H
#define OHOS_ABILITY_RUNTIME_EVENT_HUB_H
 
#include <napi/native_api.h>
#include "ability_context.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "sts_runtime.h"
 
namespace OHOS {
namespace AbilityRuntime {
 
class EventHub {
public:
    static ani_object GetDynamicContextEventHub(ani_env *env, ani_object aniObj);
    static void InitAniEventHub(ani_env *aniEnv);
    static void SetEventHubContext(ani_env *aniEnv, ani_ref eventHubRef, ani_long nativeContextLong);
 
private:
    static std::shared_ptr<AbilityContext> GetAbilityContext(ani_env *env, ani_object aniObj);
    static bool CallNapiSetNativeEventHubRefFn(ani_env *aniEnv, ani_object aniObj, napi_env napiEnv,
        napi_value eventHub);
};
 
} // namespace AbilityRuntime
} // namespace OHOS
 
#endif // OHOS_ABILITY_RUNTIME_EVENT_HUB_H