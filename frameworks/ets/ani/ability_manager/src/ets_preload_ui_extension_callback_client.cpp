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

#include "ets_preload_ui_extension_callback_client.h"

#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
EtsPreloadUIExtensionCallbackClient::~EtsPreloadUIExtensionCallbackClient()
{
    bool isAttachThread = false;
    ani_env *env = AttachAniEnv(vm_, isAttachThread);
    if (env != nullptr) {
        if (callbackRef_) {
            env->GlobalReference_Delete(callbackRef_);
            callbackRef_ = nullptr;
        }
        DetachAniEnv(vm_, isAttachThread);
    }
}

void EtsPreloadUIExtensionCallbackClient::ProcessOnLoadedDone(int32_t extensionAbilityId)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call ProcessOnLoadedDone, extensionAbilityId: %{public}d", extensionAbilityId);
    if (callbackRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "callbackRef_ null, skip");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AttachAniEnv(vm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AttachAniEnv failed");
        return;
    }
    ani_ref argv[] = { CreateInt(env, extensionAbilityId) };
    ani_ref result = nullptr;
    ani_status status = env->FunctionalObject_Call(static_cast<ani_fn_object>(callbackRef_), 1, argv, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "call callback fn failed, status: %{public}d", status);
    }
    DetachAniEnv(vm_, isAttachThread);
}

void EtsPreloadUIExtensionCallbackClient::ProcessOnDestroyDone(int32_t extensionAbilityId)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call ProcessOnDestroyDone, extensionAbilityId: %{public}d", extensionAbilityId);
    if (callbackRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "callbackRef_ null, skip");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AttachAniEnv(vm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AttachAniEnv failed");
        return;
    }
    ani_ref argv[] = { CreateInt(env, extensionAbilityId) };
    ani_ref result = nullptr;
    ani_status status = env->FunctionalObject_Call(static_cast<ani_fn_object>(callbackRef_), 1, argv, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "call callback fn failed, status: %{public}d", status);
    }
    DetachAniEnv(vm_, isAttachThread);
}
} // namespace AbilityRuntime
} // namespace OHOS