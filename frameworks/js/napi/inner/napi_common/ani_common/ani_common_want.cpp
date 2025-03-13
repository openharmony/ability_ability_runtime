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
bool WrapWantParams(ani_env* env, ani_class wantCls, ani_object wantObject, const AAFwk::WantParams& wantParams)
{
    ani_method setParametersMethod = nullptr;
    ani_status status = ANI_ERROR;
    status = env->Class_FindMethod(wantCls, "setParametersString", "Lstd/core/String;:V", &setParametersMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to get setParametersString method, status : %{public}d", status);
        return false;
    }
    nlohmann::json wantParamsJson = wantParams;
    std::string wantParamsString = wantParamsJson.dump();
    ani_string wantParamsAniString;
    status = env->String_NewUTF8(wantParamsString.c_str(), wantParamsString.length(), &wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to get setParametersString method, status : %{public}d", status);
        return false;
    }
    status = env->Object_CallMethod_Void(wantObject, setParametersMethod, wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to call setParametersString method, status : %{public}d", status);
        return false;
    }
    TAG_LOGD(AAFwkTag::JSNAPI, "WrapWantParams done");
    return true;
}

bool UnwrapWantParams(ani_env* env, ani_object wantObject, AAFwk::WantParams& wantParams)
{
    ani_class wantCls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("L@ohos/app/ability/Want/Want;", &wantCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    if (wantCls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null wantCls");
        return false;
    }

    ani_method getParametersMethod = nullptr;
    status = env->Class_FindMethod(wantCls, "getParametersString", ":Lstd/core/String;", &getParametersMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to get getParametersMethod method, status : %{public}d", status);
        return false;
    }
    ani_ref wantParamsAniString;
    status = env->Object_CallMethod_Ref(wantObject, getParametersMethod, &wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to call getParametersMethod method, status : %{public}d", status);
        return false;
    }

    std::string wantParamsString;
    if (!GetStdString(env, reinterpret_cast<ani_string>(wantParamsAniString), wantParamsString)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "GetStdString failed");
        return false;
    }
    if (wantParamsString.empty()) {
        TAG_LOGE(AAFwkTag::JSNAPI, "wantParamsString empty");
        return false;
    }
    nlohmann::json wantParamsJson = nlohmann::json::parse(wantParamsString, nullptr, false);
    if (wantParamsJson.is_discarded()) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Failed to parse json string");
        return false;
    }
    from_json(wantParamsJson, wantParams);
    TAG_LOGD(AAFwkTag::JSNAPI, "UnwrapWantParams done");
    return true;
}
}

ani_object WrapWant(ani_env *env, const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "WrapWant");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/Want/Want;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null wantCls");
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

    auto elementName = want.GetElement();
    SetFieldString(env, cls, object, "deviceId", elementName.GetDeviceID());
    SetFieldString(env, cls, object, "bundleName", elementName.GetBundleName());
    SetFieldString(env, cls, object, "abilityName", elementName.GetAbilityName());
    SetFieldString(env, cls, object, "moduleName", elementName.GetModuleName());
    SetFieldString(env, cls, object, "uri", want.GetUriString());
    SetFieldString(env, cls, object, "type", want.GetType());
    SetFieldInt(env, cls, object, "flags", want.GetFlags());
    SetFieldString(env, cls, object, "action", want.GetAction());
    WrapWantParams(env, cls, object, want.GetParams());
    SetFieldArrayString(env, cls, object, "entities", want.GetEntities());

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
        TAG_LOGE(AAFwkTag::JSNAPI, "null object");
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

bool UnwrapElementName(ani_env *env, ani_object param, ElementName &elementName)
{
    std::string deviceId;
    if (GetStringOrUndefined(env, param, "deviceId", deviceId)) {
        elementName.SetDeviceID(deviceId);
    }

    std::string bundleName;
    if (GetStringOrUndefined(env, param, "bundleName", bundleName)) {
        elementName.SetBundleName(bundleName);
    }

    std::string abilityName;
    if (GetStringOrUndefined(env, param, "abilityName", abilityName)) {
        elementName.SetAbilityName(abilityName);
    }

    std::string moduleName;
    if (GetStringOrUndefined(env, param, "moduleName", moduleName)) {
        elementName.SetModuleName(moduleName);
    }
    return true;
}

bool UnwrapWant(ani_env *env, ani_object param, AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "UnwrapWant");
    std::string action;
    if (GetStringOrUndefined(env, param, "action", action)) {
        TAG_LOGI(AAFwkTag::UIABILITY, "action %{public}s", action.c_str());
        want.SetAction(action);
    }

    std::string uri = "";
    if (GetStringOrUndefined(env, param, "uri", uri)) {
        TAG_LOGI(AAFwkTag::UIABILITY, "uri %{public}s", uri.c_str());
        want.SetUri(uri);
    }

    int flags = 0;
    if (GetIntOrUndefined(env, param, "flags", flags)) {
        TAG_LOGI(AAFwkTag::UIABILITY, "flags %{public}d", flags);
        want.SetFlags(flags);
    }

    std::string type = "";
    if (GetStringOrUndefined(env, param, "type", type)) {
        TAG_LOGI(AAFwkTag::UIABILITY, "type %{public}s", type.c_str());
        want.SetType(type);
    }

    ElementName natElementName;
    UnwrapElementName(env, param, natElementName);
    want.SetElementName(natElementName.GetDeviceID(), natElementName.GetBundleName(), natElementName.GetAbilityName(),
        natElementName.GetModuleName());

    std::vector<std::string> valueStringList;
    if (GetStringArrayOrUndefined(env, param, "entities", valueStringList)) {
        for (size_t i = 0; i < valueStringList.size(); i++) {
            want.AddEntity(valueStringList[i]);
        }
    }

    TAG_LOGE(AAFwkTag::UIABILITY,
        "DeviceID %{public}s, BundleName %{public}s, AbilityName %{public}s, ModuleName %{public}s",
        natElementName.GetDeviceID().c_str(), natElementName.GetBundleName().c_str(),
        natElementName.GetAbilityName().c_str(), natElementName.GetModuleName().c_str());

    AAFwk::WantParams wantParams;
    if (UnwrapWantParams(env, param, wantParams)) {
        want.SetParams(wantParams);
    }
    return true;
}

void UnWrapAbilityResult(ani_env *env, ani_object param, int &resultCode, AAFwk::Want &want)
{
    if (!GetIntOrUndefined(env, param, "resultCode", resultCode)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "resultCode undefined");
    }
    ani_status status = ANI_ERROR;
    ani_ref wantRef = nullptr;
    ani_boolean isUndefined = true;
    if ((status = env->Object_GetFieldByName_Ref(param, "want", &wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if ((status = env->Reference_IsUndefined(wantRef, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    if (isUndefined){
        TAG_LOGE(AAFwkTag::JSNAPI, "want undefined");
        return;
    } 
    UnwrapWant(env, reinterpret_cast<ani_object>(wantRef), want);
}
} // namespace AppExecFwk
} // namespace OHOS
