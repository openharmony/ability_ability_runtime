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

#include "ets_dialog_session_utils.h"

#include "ani_common_want.h"
#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "hilog_tag_wrapper.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char* CLASSNAME_INT = "std.core.Int";
constexpr const char* CLASSNAME_BUNDLEMANAGER_MULTIAPPMODE_TYPE =
    "@ohos.bundle.bundleManager.bundleManager.MultiAppModeType";
constexpr const char* CLASSNAME_DIALOG_ABILITY_INFO =
    "@ohos.app.ability.dialogSession.dialogSession.DialogAbilityInfoInner";
constexpr const char* CLASSNAME_DIALOG_SESSION_INFO =
    "@ohos.app.ability.dialogSession.dialogSession.DialogSessionInfoInner";
constexpr const char* CLASSNAME_MULTIAPPMODE = "bundleManager.ApplicationInfoInner.MultiAppModeInner";
ani_object WrapArrayDialogAbilityInfoToEts(ani_env *env, const std::vector<DialogAbilityInfo> &value)
{
    ani_object etsValue = nullptr;
    ani_status status = ANI_ERROR;
    ani_ref undefinedRef = nullptr;
    ani_array refArray = nullptr;

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return refArray;
    }

    if ((status = env->GetUndefined(&undefinedRef)) != ANI_OK || undefinedRef == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "GetUndefined failed, status: %{public}d or null undefinedRef", status);
        return refArray;
    }
    if ((status = env->Array_New(value.size(), undefinedRef, &refArray)) != ANI_OK
        || refArray == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "Array_New_Ref failed, status: %{public}d or null refArray", status);
        return refArray;
    }
    for (uint32_t i = 0; i < value.size(); i++) {
        etsValue = WrapDialogAbilityInfo(env, value[i]);
        if ((status = env->Array_Set(refArray, i, etsValue)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::DIALOG, "Array_Set_Ref failed, status: %{public}d", status);
            return refArray;
        }
    }

    return refArray;
}

ani_object SetDialogAbilityOtherInfo(ani_env *env, ani_object etsObject, const AAFwk::DialogAbilityInfo &info)
{
    ani_status status = env->Object_SetPropertyByName_Int(
        etsObject, "bundleLabelId", static_cast<ani_int>(info.bundleLabelId));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "bundleLabelId failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Int(
        etsObject, "abilityIconId", static_cast<ani_int>(info.abilityIconId));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "abilityIconId failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Int(
        etsObject, "abilityLabelId", static_cast<ani_int>(info.abilityLabelId));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "abilityLabelId failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Boolean(etsObject, "visible", info.visible);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "visible failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Int(etsObject, "appIndex", static_cast<ani_int>(info.appIndex));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "appIndex failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Ref(
        etsObject, "multiAppMode", WrapMultiAppModeData(env, info.multiAppMode));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "multiAppMode failed status:%{public}d", status);
    }
    return etsObject;
}
ani_object SetDialogAbilityInfo(ani_env *env, ani_object etsObject, const AAFwk::DialogAbilityInfo &info)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return etsObject;
    }
    ani_status status = env->Object_SetPropertyByName_Ref(
        etsObject, "bundleName", GetAniString(env, info.bundleName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "bundleName failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Ref(
        etsObject, "moduleName", GetAniString(env, info.moduleName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "moduleName failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Ref(
        etsObject, "abilityName", GetAniString(env, info.abilityName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "abilityName failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Int(
        etsObject, "bundleIconId", static_cast<ani_int>(info.bundleIconId));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "bundleIconId failed status:%{public}d", status);
        return etsObject;
    }
    return SetDialogAbilityOtherInfo(env, etsObject, info);
}

ani_object WrapDialogAbilityInfo(ani_env *env, const AAFwk::DialogAbilityInfo &dialogAbilityInfo)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object etsObject = nullptr;

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CLASSNAME_DIALOG_ABILITY_INFO, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null cls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "status : %{public}d", status);
        return nullptr;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null method");
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &etsObject)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "status : %{public}d", status);
        return nullptr;
    }
    if (etsObject == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null object");
        return nullptr;
    }

    return SetDialogAbilityInfo(env, etsObject, dialogAbilityInfo);
}

ani_object WrapDialogSessionInfo(ani_env *env, const AAFwk::DialogSessionInfo &dialogSessionInfo)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object etsObject = nullptr;

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CLASSNAME_DIALOG_SESSION_INFO, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindClass status : %{public}d or null cls", status);
        return AppExecFwk::CreateEtsNull(env);
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "Class_FindMethod status : %{public}d or null method", status);
        return AppExecFwk::CreateEtsNull(env);
    }
    if ((status = env->Object_New(cls, method, &etsObject)) != ANI_OK || etsObject == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "Object_New status : %{public}d or null etsObject", status);
        return AppExecFwk::CreateEtsNull(env);
    }

    status = env->Object_SetPropertyByName_Ref(
        etsObject, "callerAbilityInfo", WrapDialogAbilityInfo(env, dialogSessionInfo.callerAbilityInfo));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "callerAbilityInfo failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Ref(
        etsObject, "targetAbilityInfos", WrapArrayDialogAbilityInfoToEts(env, dialogSessionInfo.targetAbilityInfos));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "targetAbilityInfos failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Ref(
        etsObject, "parameters", AppExecFwk::WrapWantParams(env, dialogSessionInfo.parameters));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "parameters failed status:%{public}d", status);
    }
    return etsObject;
}

ani_object WrapMultiAppModeData(ani_env *env, const AppExecFwk::MultiAppModeData &multiAppMode)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object etsObject = nullptr;

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CLASSNAME_MULTIAPPMODE, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindClass status : %{public}d or null cls", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "Class_FindMethod status : %{public}d or null method", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &etsObject)) != ANI_OK || etsObject == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "Object_New status : %{public}d or null etsObject", status);
        return nullptr;
    }

    ani_enum_item modeItem = nullptr;
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(
        env, CLASSNAME_BUNDLEMANAGER_MULTIAPPMODE_TYPE, multiAppMode.multiAppModeType, modeItem);
    status = env->Object_SetPropertyByName_Ref(etsObject, "multiAppModeType", modeItem);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "multiAppModeType failed status:%{public}d", status);
        return etsObject;
    }
    status = env->Object_SetPropertyByName_Int(
        etsObject, "maxCount", static_cast<ani_int>(multiAppMode.maxCount));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "maxCount failed status:%{public}d", status);
    }

    return etsObject;
}
} // namespace AppExecFwk
} // nampspace OHOS
