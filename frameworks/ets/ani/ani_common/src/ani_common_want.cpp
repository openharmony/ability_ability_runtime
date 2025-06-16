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
#include "ani_common_util.h"
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
namespace {
bool InnerWrapWantParams(ani_env* env, ani_class wantCls, ani_object wantObject, const AAFwk::WantParams& wantParams)
{
    ani_ref wantParamRef = WrapWantParams(env, wantParams);
    if (wantParamRef == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "failed to WrapWantParams");
        return false;
    }
    return SetFieldRefByName(env, wantCls, wantObject, "parameters", wantParamRef);
}

bool InnerUnwrapWantParams(ani_env* env, ani_object wantObject, AAFwk::WantParams& wantParams)
{
    ani_ref wantParamRef = nullptr;
    if (!GetFieldRefByName(env, wantObject, "parameters", wantParamRef)) {
        TAG_LOGE(AAFwkTag::ANI, "failed to get want parameter");
        return false;
    }
    return UnwrapWantParams(env, wantParamRef, wantParams);
}
}

ani_object WrapWant(ani_env *env, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::ANI, "WrapWant called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/Want/Want;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null wantCls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null object");
        return nullptr;
    }

    auto elementName = want.GetElement();
    SetFieldStringByName(env, cls, object, "deviceId", elementName.GetDeviceID());
    SetFieldStringByName(env, cls, object, "bundleName", elementName.GetBundleName());
    SetFieldStringByName(env, cls, object, "abilityName", elementName.GetAbilityName());
    SetFieldStringByName(env, cls, object, "moduleName", elementName.GetModuleName());
    SetFieldStringByName(env, cls, object, "uri", want.GetUriString());
    SetFieldStringByName(env, cls, object, "type", want.GetType());
    SetFieldDoubleByName(env, cls, object, "flags", want.GetFlags());
    SetFieldStringByName(env, cls, object, "action", want.GetAction());
    InnerWrapWantParams(env, cls, object, want.GetParams());
    SetFieldArrayStringByName(env, cls, object, "entities", want.GetEntities());

    return object;
}

ani_ref WrapWantParams(ani_env *env, const AAFwk::WantParams &wantParams)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/Want/RecordSerializeTool;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "FindClass RecordSerializeTool failed, status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "RecordSerializeTool class null");
        return nullptr;
    }
    ani_static_method parseNoThrowMethod = nullptr;
    status = env->Class_FindStaticMethod(cls, "parseNoThrow", nullptr, &parseNoThrowMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "failed to get parseNoThrow method, status : %{public}d", status);
        return nullptr;
    }

    nlohmann::json wantParamsJson = wantParams;
    std::string wantParamsString = wantParamsJson.dump();
    ani_string wantParamsAniString;
    status = env->String_NewUTF8(wantParamsString.c_str(), wantParamsString.length(), &wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "String_NewUTF8 wantParamsString failed, status : %{public}d", status);
        return nullptr;
    }

    ani_ref wantParamsRef = nullptr;
    status = env->Class_CallStaticMethod_Ref(cls, parseNoThrowMethod, &wantParamsRef, wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "failed to call parseNoThrow method, status : %{public}d", status);
        return nullptr;
    }
    return wantParamsRef;
}

bool InnerWrapWantParamsString(
    ani_env *env, ani_object object, const std::string &key, const AAFwk::WantParams &wantParams)
{
    auto value = wantParams.GetParam(key);
    AAFwk::IString *ao = AAFwk::IString::Query(value);
    return ao != nullptr;
}

bool UnwrapElementName(ani_env *env, ani_object param, ElementName &elementName)
{
    std::string deviceId;
    if (GetFieldStringByName(env, param, "deviceId", deviceId)) {
        elementName.SetDeviceID(deviceId);
    }

    std::string bundleName;
    if (GetFieldStringByName(env, param, "bundleName", bundleName)) {
        elementName.SetBundleName(bundleName);
    }

    std::string abilityName;
    if (GetFieldStringByName(env, param, "abilityName", abilityName)) {
        elementName.SetAbilityName(abilityName);
    }

    std::string moduleName;
    if (GetFieldStringByName(env, param, "moduleName", moduleName)) {
        elementName.SetModuleName(moduleName);
    }
    return true;
}

bool UnwrapWant(ani_env *env, ani_object param, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::ANI, "UnwrapWant called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    std::string action;
    if (GetFieldStringByName(env, param, "action", action)) {
        TAG_LOGD(AAFwkTag::ANI, "action %{public}s", action.c_str());
        want.SetAction(action);
    }

    std::string uri = "";
    if (GetFieldStringByName(env, param, "uri", uri)) {
        TAG_LOGD(AAFwkTag::ANI, "uri %{public}s", uri.c_str());
        want.SetUri(uri);
    }

    double flags = 0.0;
    if (GetFieldDoubleByName(env, param, "flags", flags)) {
        TAG_LOGD(AAFwkTag::ANI, "flags %{public}f", flags);
        want.SetFlags(static_cast<int>(flags));
    }

    std::string type = "";
    if (GetFieldStringByName(env, param, "type", type)) {
        TAG_LOGD(AAFwkTag::ANI, "type %{public}s", type.c_str());
        want.SetType(type);
    }

    ElementName natElementName;
    UnwrapElementName(env, param, natElementName);
    want.SetElementName(natElementName.GetDeviceID(), natElementName.GetBundleName(), natElementName.GetAbilityName(),
        natElementName.GetModuleName());

    std::vector<std::string> valueStringList;
    if (GetFieldStringArrayByName(env, param, "entities", valueStringList)) {
        for (size_t i = 0; i < valueStringList.size(); i++) {
            want.AddEntity(valueStringList[i]);
        }
    }
    TAG_LOGD(AAFwkTag::ANI,
        "DeviceID %{public}s, BundleName %{public}s, AbilityName %{public}s, ModuleName %{public}s",
        natElementName.GetDeviceID().c_str(), natElementName.GetBundleName().c_str(),
        natElementName.GetAbilityName().c_str(), natElementName.GetModuleName().c_str());

    AAFwk::WantParams wantParams;
    if (InnerUnwrapWantParams(env, param, wantParams)) {
        want.SetParams(wantParams);
    }
    return true;
}

bool UnwrapWantParams(ani_env *env, ani_ref param, AAFwk::WantParams &wantParams)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/Want/RecordSerializeTool;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "FindClass RecordSerializeTool failed, status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "RecordSerializeTool class null");
        return false;
    }
    ani_static_method stringifyMethod = nullptr;
    status = env->Class_FindStaticMethod(cls, "stringifyNoThrow", nullptr, &stringifyMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "failed to get stringifyNoThrow method, status : %{public}d", status);
        return false;
    }
    ani_ref wantParamsAniString;
    status = env->Class_CallStaticMethod_Ref(cls, stringifyMethod, &wantParamsAniString, param);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "failed to call stringifyNoThrow method, status : %{public}d", status);
        return false;
    }
    std::string wantParamsString;
    if (!GetStdString(env, reinterpret_cast<ani_string>(wantParamsAniString), wantParamsString)) {
        TAG_LOGE(AAFwkTag::ANI, "GetStdString failed");
        return false;
    }
    if (wantParamsString.empty()) {
        TAG_LOGE(AAFwkTag::ANI, "wantParamsString empty");
        return false;
    }
    nlohmann::json wantParamsJson = nlohmann::json::parse(wantParamsString, nullptr, false);
    if (wantParamsJson.is_discarded()) {
        TAG_LOGE(AAFwkTag::ANI, "Failed to parse json string");
        return false;
    }
    from_json(wantParamsJson, wantParams);
    return true;
}

bool GetAbilityResultClass(ani_env *env, ani_class &cls)
{
    ani_status status = env->FindClass("Lability/abilityResult/AbilityResultInner;", &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetResultCode(ani_env *env, ani_object param, ani_class cls, int &resultCode)
{
    ani_method method = nullptr;
    ani_status status = env->Class_FindMethod(cls, "<get>resultCode", nullptr, &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_double dResultCode = 0.0;
    status = env->Object_CallMethod_Double(param, method, &dResultCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    resultCode = static_cast<int>(dResultCode);
    return true;
}

bool GetWantReference(ani_env *env, ani_object param, ani_class cls, ani_ref &wantRef)
{
    ani_method method {};
    ani_status status = env->Class_FindMethod(cls, "<get>want", nullptr, &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    status = env->Object_CallMethod_Ref(param, method, &wantRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    status = env->Reference_IsUndefined(wantRef, &isUndefined);
    if (status != ANI_OK || isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool UnWrapAbilityResult(ani_env *env, ani_object param, int &resultCode, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::ANI, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_class cls = nullptr;
    if (!GetAbilityResultClass(env, cls)) {
        return false;
    }
    if (!GetResultCode(env, param, cls, resultCode)) {
        return false;
    }
    ani_ref wantRef = nullptr;
    if (!GetWantReference(env, param, cls, wantRef)) {
        return false;
    }
    return UnwrapWant(env, reinterpret_cast<ani_object>(wantRef), want);
}
} // namespace AppExecFwk
} // namespace OHOS
