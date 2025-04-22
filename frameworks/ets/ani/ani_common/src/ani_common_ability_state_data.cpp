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

#include "ani_common_ability_state_data.h"

#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
ani_object WrapAbilityStateDataInner(ani_env *env, ani_class cls, ani_object object,
    const AbilityStateData &data)
{
    if (env == nullptr || cls == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid args");
        return nullptr;
    }

    if (!SetFieldString(env, cls, object, "moduleName", data.moduleName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set moduleName failed");
        return nullptr;
    }

    if (!SetFieldString(env, cls, object, "bundleName", data.bundleName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set bundleName failed");
        return nullptr;
    }

    if (!SetFieldString(env, cls, object, "abilityName", data.abilityName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set abilityName failed");
        return nullptr;
    }

    if (!SetFieldInt(env, cls, object, "pid", data.pid)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set pid failed");
        return nullptr;
    }

    if (!SetFieldInt(env, cls, object, "uid", data.uid)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set uid failed");
        return nullptr;
    }

    if (!SetFieldInt(env, cls, object, "state", data.abilityState)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set state failed");
        return nullptr;
    }

    if (!SetFieldInt(env, cls, object, "abilityType", data.abilityType)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set type failed");
        return nullptr;
    }

    if (!SetFieldBoolean(env, cls, object, "isAtomicService", data.isAtomicService)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set isAtomicService failed");
        return nullptr;
    }

    if (data.appCloneIndex != -1 && !SetOptionalFieldInt(env, cls, object, "appCloneIndex", data.appCloneIndex)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set appCloneIndex failed");
        return nullptr;
    }

    return object;
}

ani_object WrapAbilityStateData(ani_env *env, const AbilityStateData &data)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method ctor = nullptr;
    ani_object object = {};
    static const char *className = "Lability/AbilityStateData/AbilityStateData;";

    if ((status = env->FindClass(className, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "FindClass status : %{public}d or null cls", status);
        return nullptr;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &ctor)) != ANI_OK || ctor == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Class_FindMethod status : %{public}d or null ctor", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, ctor, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Object_New status : %{public}d or null object", status);
        return nullptr;
    }

    return WrapAbilityStateDataInner(env, cls, object, data);
}

ani_object CreateAniAbilityStateDataArray(ani_env *env, const std::vector<AbilityStateData> &list)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call CreateAniAbilityStateDataArray, list.size=%{public}zu", list.size());

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method ctor = nullptr;
    ani_object object = {};
    static const char *className = "Lescompat/Array;";

    if ((status = env->FindClass(className, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "FindClass status : %{public}d or null cls", status);
        return nullptr;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor)) != ANI_OK || ctor == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Class_FindMethod status : %{public}d or null ctor", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, ctor, &object, list.size())) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Object_New status : %{public}d or null object", status);
        return nullptr;
    }

    ani_size index = 0;
    for (const auto &data : list) {
        ani_object obj = WrapAbilityStateData(env, data);
        if (obj == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null obj");
            return nullptr;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(object, "$_set", "Istd/core/Object;:V", index, obj)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Object_CallMethodByName_Void failed");
            return nullptr;
        }
        index++;
    }
    return object;
}
} // namespace AppExecFwk
} // namespace OHOS