/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

#include "ets_ability_router_mgr_utils.h"

#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr const char* BUSINESS_AIBILITY_INFO_INNER_CLASS_NAME =
    "application.BusinessAbilityInfo.BusinessAbilityInfoInner";
constexpr const char* BUSINESS_TYPE_ENUM_NAME =
    "@ohos.app.businessAbilityRouter.businessAbilityRouter.BusinessType";
constexpr const char* CLASSNAME_APPLICATIONINFO =
    "bundleManager.ApplicationInfoInner.ApplicationInfoInner";
constexpr const char *CLASSNAME_ARRAY = "escompat.Array";
}

bool UnwrapBusinessAbilityFilter(ani_env *env, ani_object param, BusinessAbilityFilter &filter)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "UnwrapBusinessAbilityFilter called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return false;
    }
    int32_t businessType = static_cast<int32_t>(BusinessType::UNSPECIFIED);
    ani_ref businessTypeRef = nullptr;
    ani_status status = env->Object_GetPropertyByName_Ref(param, "businessType", &businessTypeRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Unwrap businessType failed");
        return false;
    }
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
        env, reinterpret_cast<ani_enum_item>(businessTypeRef), businessType);

    int32_t minType = static_cast<int32_t>(BusinessType::SHARE);
    int32_t maxType = static_cast<int32_t>(BusinessType::SHARE);
    if (businessType < minType || businessType > maxType) {
        businessType = static_cast<int32_t>(BusinessType::UNSPECIFIED);
    }
    filter.businessType = static_cast<BusinessType>(businessType);

    ani_boolean isUndefined = true;
    std::string mimeType = "";
    ani_ref mimeTypeRef = nullptr;
    if (!GetPropertyRef(env, param, "mimeType", mimeTypeRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Unwrap mimeType failed");
        return false;
    }
    if (!isUndefined && !GetStdString(env, reinterpret_cast<ani_string>(mimeTypeRef), mimeType)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Failed to get uri string from uriRef");
        return false;
    }
    std::string uri = "";
    ani_ref uriRef = nullptr;
    if (!GetPropertyRef(env, param, "uri", uriRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Unwrap uri failed");
        return false;
    }
    if (!isUndefined && !GetStdString(env, reinterpret_cast<ani_string>(uriRef), uri)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Failed to get uri string from uriRef");
        return false;
    }
    filter.mimeType = mimeType;
    filter.uri = uri;
    return true;
}

ani_object ConvertBusinessAbilityInfos(ani_env *env, const std::vector<BusinessAbilityInfo> &infos)
{
    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }

    status = env->FindClass(CLASSNAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "FindClass failed status : %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor failed status : %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, infos.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Object_New array status : %{public}d", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto &info : infos) {
        ani_object ani_info = ConvertBusinessAbilityInfo(env, info);
        if (ani_info == nullptr) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "null ani_info");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, ani_info);
        if (status != ANI_OK) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "Object_CallMethodByName_Void failed status : %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}

ani_object ConvertBusinessAbilityInfo(ani_env *env, const BusinessAbilityInfo &info)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_method method {};
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(BUSINESS_AIBILITY_INFO_INNER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find class failed status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null cls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor failed status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Object_New failed status : %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null object");
        return nullptr;
    }
    if (!WrapBusinessAbilityInfo(env, cls, object, info)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "WrapBusinessAbilityInfo failed");
        return nullptr;
    }
    return object;
}

bool WrapBusinessAbilityInfo(ani_env *env, ani_class cls, ani_object object,
    const BusinessAbilityInfo &info)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return false;
    }
    ani_status status = ANI_OK;
    if ((status = env->Object_SetPropertyByName_Ref(object, "bundleName",
        GetAniString(env, info.bundleName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "bundleName failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, "moduleName",
        GetAniString(env, info.moduleName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "moduleName failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, "name", GetAniString(env, info.abilityName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "abilityName failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Int(object, "labelId", info.labelId)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "labelId failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Int(object, "descriptionId", info.descriptionId)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "descriptionId failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Int(object, "iconId", info.iconId)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "iconId failed status:%{public}d", status);
        return false;
    }
    ani_enum_item typeItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, BUSINESS_TYPE_ENUM_NAME, info.businessType, typeItem);
    if ((status = env->Object_SetPropertyByName_Ref(object, "businessType", typeItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "businessType failed status:%{public}d", status);
        return false;
    }
    ani_field appInfoField;
    if ((status = env->Class_FindField(cls, "applicationInfo", &appInfoField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find applicationInfo failed:%{public}d", status);
        return false;
    }
    ani_object appInfoObj = ConvertAppInfo(env, info.appInfo);
    if ((status = env->Object_SetField_Ref(object, appInfoField, reinterpret_cast<ani_ref>(appInfoObj))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Object_SetField_Ref failed:%{public}d", status);
        return false;
    }
    return true;
}

ani_object ConvertAppInfo(ani_env *env, const AppInfo &appInfo)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_method method {};
    ani_object object = nullptr;
    if (appInfo.bundleName.empty()) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "bundleName empty");
        return nullptr;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CLASSNAME_APPLICATIONINFO, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find class failed status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null cls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor failed status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Object_New failed status : %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null object");
        return nullptr;
    }
    if (!WrapApplicationInfo(env, object, appInfo)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "WrapApplicationInfo failed");
        return nullptr;
    }
    return object;
}

bool WrapApplicationInfo(ani_env *env, ani_object object, const AppInfo &appInfo)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return false;
    }
    ani_status status = ANI_OK;
    if ((status = env->Object_SetPropertyByName_Ref(object, "name",
        GetAniString(env, appInfo.bundleName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "name failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Long(object, "labelId", appInfo.labelId)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "labelId failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Long(object, "descriptionId", appInfo.descriptionId)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "descriptionId failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Long(object, "iconId", appInfo.iconId)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "iconId failed status:%{public}d", status);
        return false;
    }
    return true;
}
}  // namespace AbilityRuntime
}  // namespace OHOS