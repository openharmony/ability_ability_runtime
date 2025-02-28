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

#include "ani_common_want.h"
#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "byte_wrapper.h"
#include "double_wrapper.h"
#include "float_wrapper.h"
#include "hilog_tag_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "js_runtime_utils.h"
#include "long_wrapper.h"
#include "napi_remote_object.h"
#include "remote_object_wrapper.h"
#include "short_wrapper.h"
#include "string_wrapper.h"
#include "tokenid_kit.h"
#include "want_params_wrapper.h"
#include "zchar_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AbilityRuntime;

ani_object WrapWant(ani_env *env, const AAFwk::Want &want)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "WrapWant");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    ani_field field = nullptr;
    ani_string string = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/Want/Want;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantCls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null object");
        return nullptr;
    }

    auto elementName = want.GetElement();
    if ((status = env->Class_FindField(cls, "deviceId", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    env->String_NewUTF8(elementName.GetDeviceID().c_str(), elementName.GetDeviceID().size(), &string);
    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "bundleName", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->String_NewUTF8(
             elementName.GetBundleName().c_str(), elementName.GetBundleName().size(), &string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    env->Class_FindField(cls, "abilityName", &field);
    env->String_NewUTF8(elementName.GetAbilityName().c_str(), elementName.GetAbilityName().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    env->Class_FindField(cls, "moduleName", &field);
    env->String_NewUTF8(elementName.GetModuleName().c_str(), elementName.GetModuleName().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    env->Class_FindField(cls, "uri", &field);
    env->String_NewUTF8(want.GetUriString().c_str(), want.GetUriString().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    env->Class_FindField(cls, "type", &field);
    env->String_NewUTF8(want.GetType().c_str(), want.GetType().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    if ((status = env->Class_FindField(cls, "flags", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Int(object, field, want.GetFlags())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    env->Class_FindField(cls, "action", &field);
    env->String_NewUTF8(want.GetAction().c_str(), want.GetAction().size(), &string);
    env->Object_SetField_Ref(object, field, string);
    // TODO
    return object;
}

ani_object WrapWantParams(ani_env *env, ani_class cls, const AAFwk::WantParams &wantParams)
{
    ani_method method = nullptr;
    ani_object object = nullptr;
    env->Class_FindMethod(cls, "<init>", "I:V", &method);
    env->Object_New(cls, method, &object);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null object");
        return nullptr;
    }
    // TODO
    return object;
}

bool InnerWrapWantParamsString(
    ani_env *env, ani_object object, const std::string &key, const AAFwk::WantParams &wantParams)
{
    auto value = wantParams.GetParam(key);
    AAFwk::IString *ao = AAFwk::IString::Query(value);
    if (ao == nullptr) {
        return false;
    }
    // TODO
    return true;
}

std::string GetStdString(ani_env *env, ani_string str)
{
    std::string result;
    ani_size sz {};
    env->String_GetUTF8Size(str, &sz);
    result.resize(sz + 1);
    env->String_GetUTF8SubString(str, 0, sz, result.data(), result.size(), &sz);
    result.resize(sz);
    return result;
}

bool UnwrapElementName(ani_env *env, ani_object param, ElementName &elementName)
{
    ani_ref deviceIdRef {};
    env->Object_GetFieldByName_Ref(param, "deviceId", &deviceIdRef);
    ani_string deviceIdAni = reinterpret_cast<ani_string>(deviceIdRef);
    std::string deviceId = GetStdString(env, deviceIdAni);
    elementName.SetDeviceID(deviceId);

    ani_ref bundleNameRef {};
    env->Object_GetFieldByName_Ref(param, "bundleName", &bundleNameRef);
    ani_string bundleNameAni = reinterpret_cast<ani_string>(bundleNameRef);
    std::string bundleName = GetStdString(env, bundleNameAni);
    elementName.SetBundleName(bundleName);

    ani_ref abilityNameRef {};
    env->Object_GetFieldByName_Ref(param, "abilityName", &abilityNameRef);
    ani_string abilityNameAni = reinterpret_cast<ani_string>(abilityNameRef);
    std::string abilityName = GetStdString(env, abilityNameAni);
    elementName.SetAbilityName(abilityName);

    ani_ref moduleNameRef {};
    env->Object_GetFieldByName_Ref(param, "moduleName", &moduleNameRef);
    ani_string moduleNameAni = reinterpret_cast<ani_string>(moduleNameRef);
    std::string moduleName = GetStdString(env, moduleNameAni);
    elementName.SetModuleName(moduleName);
    return true;
}

bool UnwrapWant(ani_env *env, ani_object param, AAFwk::Want &want)
{
    ani_ref actionRef {};
    env->Object_GetFieldByName_Ref(param, "action", &actionRef);
    ani_string actionAni = reinterpret_cast<ani_string>(actionRef);
    std::string action = GetStdString(env, actionAni);

    ani_ref uriRef {};
    env->Object_GetFieldByName_Ref(param, "uri", &uriRef);
    ani_string uriAni = reinterpret_cast<ani_string>(uriRef);
    std::string uri = GetStdString(env, uriAni);

    ani_int flags {};
    env->Object_GetFieldByName_Int(param, "flags", &flags);
    want.SetFlags(flags);

    ani_ref typeRef {};
    env->Object_GetFieldByName_Ref(param, "type", &typeRef);
    ani_string typeAni = reinterpret_cast<ani_string>(typeRef);
    std::string type = GetStdString(env, typeAni);

    ElementName natElementName;
    UnwrapElementName(env, param, natElementName);
    want.SetElementName(natElementName.GetDeviceID(), natElementName.GetBundleName(), natElementName.GetAbilityName(),
        natElementName.GetModuleName());
    // TODO
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
