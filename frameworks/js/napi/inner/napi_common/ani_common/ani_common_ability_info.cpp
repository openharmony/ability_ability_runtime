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

#include "ani_common_ability_info.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

ani_object WrapAbilityInfo(ani_env *env, const AbilityInfo &abilityInfo)
{
    TAG_LOGE(AAFwkTag::JSNAPI, "WrapAbilityInfo");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;

    if ((status = env->FindClass("LbundleManager/AbilityInfo/AbilityInfoCls;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null AbilityInfoCls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null object");
        return nullptr;
    }

    ClassSetter(env, cls, object, SETTER_METHOD_NAME(bundleName), GetAniString(env, abilityInfo.bundleName));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), GetAniString(env, abilityInfo.moduleName));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(name), GetAniString(env, abilityInfo.name));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(label), GetAniString(env, abilityInfo.label));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(description), GetAniString(env, abilityInfo.description));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(icon), GetAniString(env, abilityInfo.iconPath));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(process), GetAniString(env, abilityInfo.process));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(readPermission), GetAniString(env, abilityInfo.readPermission));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(writePermission), GetAniString(env, abilityInfo.writePermission));
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(uri), GetAniString(env, abilityInfo.uri));

    ClassSetter(env, cls, object, SETTER_METHOD_NAME(labelId), abilityInfo.labelId);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(descriptionId), abilityInfo.descriptionId);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(iconId), abilityInfo.iconId);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(appIndex), abilityInfo.appIndex);
    // ClassSetter(env, cls, object, SETTER_METHOD_NAME(orientationId), abilityInfo.orientationId);
    // ClassSetter(env, cls, object, SETTER_METHOD_NAME(exported), abilityInfo.enabled);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(enabled), abilityInfo.enabled);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(excludeFromDock), abilityInfo.formEnabled);
    
    // ClassSetter(env, cls, object, SETTER_METHOD_NAME(permissions), GetAniArrayString(env, abilityInfo.permissions));
    // ClassSetter(env, cls, object, SETTER_METHOD_NAME(deviceTypes), GetAniArrayString(env, abilityInfo.deviceTypes));


    // Wrap permissions
    // Wrap other fields similarly...
    return object;
}

}  // namespace AppExecFwk
}  // namespace OHOS
