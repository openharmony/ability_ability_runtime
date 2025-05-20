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
#include "long_wrapper.h"
#include "short_wrapper.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "zchar_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* WANT_CLASS_NAME = "L@ohos/app/ability/Want/Want;";
constexpr const char* RECORD_SERIALIZE_TOOL_CLASS_NAME = "L@ohos/app/ability/Want/RecordSerializeTool;";
constexpr const char* ABILITY_RESULT_INNER_CLASS_NAME = "Lability/abilityResult/AbilityResultInner;";

bool InnerWrapWantParams(ani_env* env, ani_class wantCls, ani_object wantObject, const AAFwk::WantParams& wantParams)
{
    ani_ref wantParamRef = WrapWantParams(env, wantParams);
    if (wantParamRef == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to WrapWantParams");
        return false;
    }
    return SetFieldRef(env, wantCls, wantObject, "parameters", wantParamRef);
}

bool InnerUnwrapWantParams(ani_env* env, ani_object wantObject, AAFwk::WantParams& wantParams)
{
    ani_ref wantParamRef = nullptr;
    if (!GetRefFieldByName(env, wantObject, "parameters", wantParamRef)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to get want parameter");
        return false;
    }
    return UnwrapWantParams(env, wantParamRef, wantParams);
}
}

ani_object WrapWant(ani_env *env, const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "WrapWant");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass(WANT_CLASS_NAME, &cls)) != ANI_OK) {
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
    env->Object_SetFieldByName_Ref(object, "deviceId", GetAniString(env, elementName.GetDeviceID()));
    env->Object_SetFieldByName_Ref(object, "bundleName", GetAniString(env, elementName.GetBundleName()));
    env->Object_SetFieldByName_Ref(object, "abilityName", GetAniString(env, elementName.GetAbilityName()));
    env->Object_SetFieldByName_Ref(object, "moduleName", GetAniString(env, elementName.GetModuleName()));
    env->Object_SetFieldByName_Ref(object, "uri", GetAniString(env, want.GetUriString()));
    env->Object_SetFieldByName_Ref(object, "type", GetAniString(env, want.GetType()));
    env->Object_SetFieldByName_Ref(object, "flags", createDouble(env, want.GetFlags()));
    env->Object_SetFieldByName_Ref(object, "action", GetAniString(env, want.GetAction()));
    InnerWrapWantParams(env, cls, object, want.GetParams());
    SetFieldArrayString(env, cls, object, "entities", want.GetEntities());
    return object;
}

ani_ref WrapWantParams(ani_env *env, const AAFwk::WantParams &wantParams)
{
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(RECORD_SERIALIZE_TOOL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "FindClass RecordSerializeTool failed, status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "RecordSerializeTool class null");
        return nullptr;
    }
    ani_static_method parseNoThrowMethod = nullptr;
    status = env->Class_FindStaticMethod(cls, "parseNoThrow", nullptr, &parseNoThrowMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to get parseNoThrow method, status : %{public}d", status);
        return nullptr;
    }

    nlohmann::json wantParamsJson = wantParams;
    std::string wantParamsString = wantParamsJson.dump();
    ani_string wantParamsAniString;
    status = env->String_NewUTF8(wantParamsString.c_str(), wantParamsString.length(), &wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "String_NewUTF8 wantParamsString failed, status : %{public}d", status);
        return nullptr;
    }

    ani_ref wantParamsRef = nullptr;
    status = env->Class_CallStaticMethod_Ref(cls, parseNoThrowMethod, &wantParamsRef, wantParamsAniString);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to call parseNoThrow method, status : %{public}d", status);
        return nullptr;
    }
    return wantParamsRef;
}

ani_object WrapElementName(ani_env *env, const AppExecFwk::ElementName &elementNameParam)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "WrapElementName");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return nullptr;
    }
    ani_class elementNameObj = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = {};
    static const char *className = "LbundleManager/ElementNameInner/ElementNameInner;";
    if ((status = env->FindClass(className, &elementNameObj)) != ANI_OK || elementNameObj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "FindClass status : %{public}d or null elementNameObj", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(elementNameObj, "<ctor>", ":V", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Class_FindMethod status : %{public}d or null method", status);
        return nullptr;
    }
    if ((status = env->Object_New(elementNameObj, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Object_New status : %{public}d or null object", status);
        return nullptr;
    }
    return WrapElementNameInner(env, elementNameObj, object, elementNameParam);
}

ani_object WrapElementNameInner(ani_env *env, ani_class elementNameObj, ani_object object,
    const AppExecFwk::ElementName &elementNameParam)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "WrapElementNameInner");
    if (env == nullptr || elementNameObj == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid args");
        return nullptr;
    }
    if (!SetFieldString(env, elementNameObj, object, "bundleName", elementNameParam.GetBundleName())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set bundleName failed");
        return nullptr;
    }
    if (!SetFieldString(env, elementNameObj, object, "abilityName", elementNameParam.GetAbilityName())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set abilityName failed");
        return nullptr;
    }
    if (!SetStringProperty(env, object, "deviceId", elementNameParam.GetDeviceID())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set deviceId failed");
    }
    if (!SetStringProperty(env, object, "moduleName", elementNameParam.GetModuleName())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set moduleName failed");
    }
    if (!SetStringProperty(env, object, "uri", elementNameParam.GetURI())) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set uri failed");
    }
    return object;
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

    ani_double flags = 0.0;
    if (GetDoubleOrUndefined(env, param, "flags", flags)) {
        TAG_LOGI(AAFwkTag::UIABILITY, "flags %{public}f", flags);
        want.SetFlags(static_cast<int>(flags));
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

    TAG_LOGD(AAFwkTag::UIABILITY,
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
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(RECORD_SERIALIZE_TOOL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "FindClass RecordSerializeTool failed, status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "RecordSerializeTool class null");
        return false;
    }

    ani_static_method stringifyMethod = nullptr;
    status = env->Class_FindStaticMethod(cls, "stringifyNoThrow", nullptr, &stringifyMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to get stringifyNoThrow method, status : %{public}d", status);
        return false;
    }
    ani_ref wantParamsAniString;
    status = env->Class_CallStaticMethod_Ref(cls, stringifyMethod, &wantParamsAniString, param);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "failed to call stringifyNoThrow method, status : %{public}d", status);
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
    return true;
}

bool GetAbilityResultClass(ani_env *env, ani_class &cls)
{
    ani_status status = env->FindClass(ABILITY_RESULT_INNER_CLASS_NAME, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetResultCode(ani_env *env, ani_object param, ani_class cls, int &resultCode)
{
    ani_method method {};
    ani_status status = env->Class_FindMethod(cls, "<get>resultCode", nullptr, &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
        return false;
    }
    ani_double dResultCode = 0.0;
    status = env->Object_CallMethod_Double(param, method, &dResultCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
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
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
        return false;
    }
    status = env->Object_CallMethod_Ref(param, method, &wantRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = true;
    status = env->Reference_IsUndefined(wantRef, &isUndefined);
    if (status != ANI_OK || isUndefined) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool UnWrapAbilityResult(ani_env *env, ani_object param, int &resultCode, AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "env is null");
        return false;
    }
    ani_class cls {};
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
