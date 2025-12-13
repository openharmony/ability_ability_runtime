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

#include "etc_quick_fix_mgr.h"

#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "quick_fix_manager_client.h"
#include "quick_fix_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace quickFixManager {
namespace {

constexpr const int32_t ERR_OK = 0;
constexpr const char *CLASSNAME_ARRAY = "std.core.Array";
constexpr const char *QUICK_FIX_INFO_CLASS_NAME =
    "@ohos.app.ability.quickFixManager.quickFixManager.ApplicationQuickFixInfoImpl";
constexpr const char *HAP_MODULE_QUICK_FIX_INFO_IMPL_CLASS_NAME =
    "@ohos.app.ability.quickFixManager.quickFixManager.HapModuleQuickFixInfoImpl";

ani_object WrapHapModuleQuickFixInfo(ani_env *env, const AppExecFwk::HqfInfo &hqfInfo)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "WrapHapModuleQuickFixInfo");
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_method method {};
    ani_object object = nullptr;
    
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null env");
        return nullptr;
    }
    
    status = env->FindClass(HAP_MODULE_QUICK_FIX_INFO_IMPL_CLASS_NAME, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "Find HapModuleQuickFixInfoImpl Class failed");
        return nullptr;
    }

    status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
    if (status != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return nullptr;
    }
    
    status = env->Object_New(cls, method, &object);
    if (status != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return nullptr;
    }

    status = env->Object_SetPropertyByName_Ref(object, "moduleName",
        OHOS::AppExecFwk::GetAniString(env, hqfInfo.moduleName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "moduleName failed status:%{public}d", status);
        return nullptr;
    }

    status = env->Object_SetPropertyByName_Ref(object, "originHapHash",
        OHOS::AppExecFwk::GetAniString(env, hqfInfo.hapSha256));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "originHapHash failed status:%{public}d", status);
        return nullptr;
    }

    status = env->Object_SetPropertyByName_Ref(object, "quickFixFilePath",
        OHOS::AppExecFwk::GetAniString(env, hqfInfo.hqfFilePath));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "quickFixFilePath failed status:%{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object WrapHapModuleQuickFixInfoArray(ani_env *env, const std::vector<AppExecFwk::HqfInfo> &hqfInfos)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "WrapHapModuleQuickFixInfoArray");
    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;
    ani_method arrayCtor = nullptr;
    ani_object arrayObj = nullptr;
    
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null env");
        return nullptr;
    }
    
    status = env->FindClass(CLASSNAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return nullptr;
    }
    
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return nullptr;
    }

    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, hqfInfos.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return arrayObj;
    }

    ani_size index = 0;
    for (auto &hqfInfo : hqfInfos) {
        ani_ref ani_info = WrapHapModuleQuickFixInfo(env, hqfInfo);
        if (ani_info == nullptr) {
            TAG_LOGE(AAFwkTag::QUICKFIX, "null ani_info");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, ani_info);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}

bool SetBasicConfiguration(ani_env *env, ani_object object, const AAFwk::ApplicationQuickFixInfo &appQuickFixInfo)
{
    if (env == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null env or object");
        return false;
    }

    ani_status status = ANI_ERROR;
    status = env->Object_SetPropertyByName_Ref(object, "bundleName",
        AppExecFwk::GetAniString(env, appQuickFixInfo.bundleName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "bundleName failed status:%{public}d", status);
        return false;
    }
    
    status = env->Object_SetPropertyByName_Long(object, "bundleVersionCode",
        appQuickFixInfo.bundleVersionCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "bundleVersionCodeLong SetField status: %{public}d", status);
        return false;
    }
    
    status = env->Object_SetPropertyByName_Ref(object, "bundleVersionName",
        AppExecFwk::GetAniString(env, appQuickFixInfo.bundleVersionName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "bundleVersionName failed status:%{public}d", status);
        return false;
    }
    
    status = env->Object_SetPropertyByName_Long(object, "quickFixVersionCode",
        appQuickFixInfo.appqfInfo.versionCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "quickFixVersionCode SetField status: %{public}d", status);
        return false;
    }

    status = env->Object_SetPropertyByName_Ref(object, "quickFixVersionName",
        AppExecFwk::GetAniString(env, appQuickFixInfo.appqfInfo.versionName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "quickFixVersionName failed status:%{public}d", status);
        return false;
    }
    return true;
}

ani_object WrapEtsApplicationQuickFixInfo(ani_env *env, const AAFwk::ApplicationQuickFixInfo &appQuickFixInfo)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "WrapEtsApplicationQuickFixInfo");
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_method method {};
    ani_object object = nullptr;
    
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null env");
        return nullptr;
    }
    
    status = env->FindClass(QUICK_FIX_INFO_CLASS_NAME, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "Find ApplicationQuickFixInfoImpl Class failed");
        return nullptr;
    }
    
    status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
    if (status != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return nullptr;
    }
    
    status = env->Object_New(cls, method, &object);
    if (status != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "status : %{public}d", status);
        return nullptr;
    }
    
    if (!SetBasicConfiguration(env, object, appQuickFixInfo)) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "SetBasicConfiguration failed");
        return nullptr;
    }

    status = env->Object_SetPropertyByName_Ref(object, "hapModuleQuickFixInfo",
        WrapHapModuleQuickFixInfoArray(env, appQuickFixInfo.appqfInfo.hqfInfos));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "hapModuleQuickFixInfo failed status:%{public}d", status);
        return nullptr;
    }
    return object;
}

}

static void applyQuickFixSync([[maybe_unused]]ani_env *env,
    ani_object aniHapModuleQuickFixFiles, ani_object callback)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "applyQuickFixSync run");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "env null");
        return;
    }
    
    std::vector<std::string> hapQuickFixFiles;
    ani_boolean isUndefined = false;
    ani_status status = ANI_OK;
    if ((status = env->Reference_IsUndefined(aniHapModuleQuickFixFiles, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "Failed to check undefined status : %{public}d", status);
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    if (!isUndefined && !AppExecFwk::UnwrapArrayString(env, aniHapModuleQuickFixFiles, hapQuickFixFiles)) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "GetStdString failed");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }

    auto quickFixMgr = AAFwk::QuickFixManagerClient::GetInstance();
    if (quickFixMgr == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null quickFixMgr");
        return;
    }

    auto errCode = quickFixMgr->ApplyQuickFix(hapQuickFixFiles);
    if (errCode == ERR_OK) {
        TAG_LOGD(AAFwkTag::QUICKFIX, "applyQuickFixSync success, will callback");
        AppExecFwk::AsyncCallback(env, callback, nullptr, nullptr);
    } else {
        TAG_LOGD(AAFwkTag::QUICKFIX, "get quickFixInfo failed, errcode:%{public}d", errCode);
        auto externalErrCode = AAFwk::QuickFixErrorUtil::GetErrorCode(errCode);
        auto errMsg = AAFwk::QuickFixErrorUtil::GetErrorMessage(errCode);
        auto etsErrObj = EtsErrorUtil::CreateError(env, externalErrCode, errMsg);
        AppExecFwk::AsyncCallback(env, callback, etsErrObj, nullptr);
    }
}

static void revokeQuickFixSync([[maybe_unused]]ani_env *env,
    ani_string aniBundleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "revokeQuickFixSync run");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "env null");
        return;
    }
    
    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "invalid param");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }

    auto quickFixMgr = AAFwk::QuickFixManagerClient::GetInstance();
    if (quickFixMgr == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null quickFixMgr");
        return;
    }
    
    auto errCode = quickFixMgr->RevokeQuickFix(bundleName);
    if (errCode == ERR_OK) {
        TAG_LOGD(AAFwkTag::QUICKFIX, "revokeQuickFixSync success, will callback");
        auto etsErrObj = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
        AppExecFwk::AsyncCallback(env, callback, etsErrObj, nullptr);
    } else {
        TAG_LOGD(AAFwkTag::QUICKFIX, "get revokeQuickFixSync failed, errcode:%{public}d", errCode);
        auto externalErrCode = AAFwk::QuickFixErrorUtil::GetErrorCode(errCode);
        auto errMsg = AAFwk::QuickFixErrorUtil::GetErrorMessage(errCode);
        auto etsErrObj = EtsErrorUtil::CreateError(env, externalErrCode, errMsg);
        AppExecFwk::AsyncCallback(env, callback, etsErrObj, nullptr);
    }
}

static void getApplicationQuickFixInfoSync([[maybe_unused]]ani_env *env,
    ani_string aniBundleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "getApplicationQuickFixInfoSync run");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "env null");
        return;
    }

    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "invalid param");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }

    auto quickFixMgr = AAFwk::QuickFixManagerClient::GetInstance();
    if (quickFixMgr == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "null quickFixMgr");
        return;
    }

    AAFwk::ApplicationQuickFixInfo quickFixInfo;
    auto errCode = quickFixMgr->GetApplyedQuickFixInfo(
        bundleName, quickFixInfo);
    if (errCode == ERR_OK) {
        TAG_LOGD(AAFwkTag::QUICKFIX, "get quickFixInfo success, will callback");
        auto aniQuickFixInfo = WrapEtsApplicationQuickFixInfo(env, quickFixInfo);
        AppExecFwk::AsyncCallback(env, callback, nullptr, aniQuickFixInfo);
    } else {
        TAG_LOGD(AAFwkTag::QUICKFIX, "get quickFixInfo failed, errcode:%{public}d", errCode);
        auto externalErrCode = AAFwk::QuickFixErrorUtil::GetErrorCode(errCode);
        auto errMsg = AAFwk::QuickFixErrorUtil::GetErrorMessage(errCode);
        auto etsErrObj = EtsErrorUtil::CreateError(env, externalErrCode, errMsg);
        AppExecFwk::AsyncCallback(env, callback, etsErrObj, nullptr);
    }
}

void EtsQuickFixManagerInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::QUICKFIX, "EtsQuickFixManagerInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "Invalid param");
        return;
    }
    ani_namespace ns;
    const char* targetNamespace = "@ohos.app.ability.quickFixManager.quickFixManager";
    if (env->FindNamespace(targetNamespace, &ns) != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "FindNamespace failed");
    }
    if (ns == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "ns null");
        return;
    }
    std::array functions = {
        ani_native_function {
            "applyQuickFixSync",
            "C{std.core.Array}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void*>(applyQuickFixSync)
        },
        ani_native_function {
            "revokeQuickFixSync",
            "C{std.core.String}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void*>(revokeQuickFixSync)
        },
        ani_native_function {
            "getApplicationQuickFixInfoSync",
            "C{std.core.String}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void*>(getApplicationQuickFixInfoSync)
        },
    };
    TAG_LOGD(AAFwkTag::QUICKFIX, "EtsQuickFixManagerInit bind functions");
    if (env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "Namespace_BindNativeFunctions failed");
    };
    TAG_LOGD(AAFwkTag::QUICKFIX, "EtsQuickFixManagerInit end");
}

extern "C"{
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::QUICKFIX, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "vm null");
        return ANI_ERROR;
    }
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::QUICKFIX, "result null");
        return ANI_ERROR;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::QUICKFIX, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsQuickFixManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::QUICKFIX, "ANI_Constructor finish");
    return ANI_OK;
}
}

}
} // namespace AbilityRuntime
} // namespace OHOS
