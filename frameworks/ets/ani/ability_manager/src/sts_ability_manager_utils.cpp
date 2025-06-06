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

#include "sts_ability_manager_utils.h"

#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"

namespace OHOS {
namespace AbilityManagerSts {
constexpr const char *CLASSNAME_ARRAY = "Lescompat/Array;";
constexpr const char *SET_OBJECT_VOID_SIGNATURE = "ILstd/core/Object;:V";
constexpr const char *CLASSNAME_ABILITY_RRUNNINGINFO = "Lapplication/AbilityRunningInfo/AbilityRunningInfoImpl;";
constexpr const char *ABILITY_STATE_ENUM_NAME = "L@ohos/app/ability/abilityManager/abilityManager/AbilityState;";

bool WrapAbilityRunningInfoArray(
    ani_env *env, ani_object &arrayObj, const std::vector<AAFwk::AbilityRunningInfo> &infos)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "WrapAbilityRunningInfoArray");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return false;
    }
    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_ARRAY, &arrayCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "status : %{public}d", status);
        return false;
    }
    if (arrayCls == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null arrayCls");
        return false;
    }
    if ((status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "status : %{public}d", status);
        return false;
    }
    if (arrayCtor == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null arrayCtor");
        return false;
    }
    if ((status = env->Object_New(arrayCls, arrayCtor, &arrayObj, infos.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "status : %{public}d", status);
        return false;
    }
    if (arrayObj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null arrayObjs");
        return false;
    }
    for (size_t i = 0; i < infos.size(); i++) {
        ani_object infoObj = nullptr;
        if (!WrapAbilityRunningInfo(env, infoObj, infos[i])) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "WrapAbilityRunningInfo failed");
            return false;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", SET_OBJECT_VOID_SIGNATURE, i, infoObj);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "status : %{public}d", status);
            return false;
        }
    }
    return true;
}

bool WrapAbilityRunningInfo(ani_env *env, ani_object &infoObj, const AAFwk::AbilityRunningInfo &info)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "WrapAbilityRunningInfo");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return false;
    }
    ani_object elementNameObj = WrapElementName(env, info.ability);
    if (elementNameObj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "WrapElementName failed");
        return false;
    }
    ani_class cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_ABILITY_RRUNNINGINFO, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "findClass failed, status: %{public}d", status);
        return false;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null cls");
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "findMethod failed, status: %{public}d", status);
        return false;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null method");
        return false;
    }
    if ((status = env->Object_New(cls, method, &infoObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Object_New failed, status: %{public}d", status);
        return false;
    }
    if (infoObj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null infoObj");
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(infoObj, "ability", elementNameObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set ability failed, status: %{public}d", status);
        return false;
    }
    return WrapAbilityRunningInfoInner(env, infoObj, info, cls);
}

bool WrapAbilityRunningInfoInner(
    ani_env *env, ani_object &infoObj, const AAFwk::AbilityRunningInfo &info, ani_class cls)
{
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Double(infoObj, "pid", info.pid)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set pid failed, status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Double(infoObj, "uid", info.uid)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set uid failed, status: %{public}d", status);
        return false;
    }
    if (!AppExecFwk::SetFieldString(env, cls, infoObj, "processName", info.processName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set processName failed");
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Double(infoObj, "startTime", info.startTime)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set processName failed, status: %{public}d", status);
        return false;
    }
    ani_enum_item abilityStateItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(
        env, ABILITY_STATE_ENUM_NAME, info.abilityState, abilityStateItem);
    if ((status = env->Object_SetPropertyByName_Ref(infoObj, "abilityState", abilityStateItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set abilityState failed, status: %{public}d", status);
        return false;
    }
    return true;
}
} // namespace AbilityManagerSts
} // namespace OHOS