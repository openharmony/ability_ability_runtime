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

#include "ani_common_remote.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object AniRemote::CreateAniRemoteObject(ani_env *env, const sptr<IRemoteObject> target)
{
    ani_status status = ANI_ERROR;
    ani_class cls {};
    ani_method method = nullptr;
    if ((status = env->FindClass("L@ohos/rpc/rpc/RemoteProxy;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "FindClass RemoteProxy: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "RemoteProxy ctor: %{public}d", status);
        return nullptr;
    }
    ani_object remoteObj = nullptr;
    if ((status = env->Object_New(cls, method, &remoteObj, (ani_long)(target.GetRefPtr()))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "RemoteProxy create: %{public}d", status);
        return nullptr;
    }
    return remoteObj;
}
} // namespace AbilityRuntime
} // namespace OHOS