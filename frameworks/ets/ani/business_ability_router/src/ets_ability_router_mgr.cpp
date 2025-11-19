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

#include "ets_ability_router_mgr.h"

#include "ani_common_util.h"
#include "appexecfwk_errors.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ets_ability_router_mgr_utils.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "iservice_router_mgr.h"
#include "service_router_mgr_helper.h"
#include "service_router_mgr_proxy.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr const char* ETS_DELEGATOR_REGISTRY_NAMESPACE =
    "L@ohos/app/businessAbilityRouter/businessAbilityRouter;";
constexpr const char* TYPE_BUSINESS_AIBILITY_FILTER = "businessAbilityFilter";
constexpr const char* QUERY_BUSINESS_ABILITY_INFO = "queryBusinessAbilityInfo";
}

EtsAbilityRouterMgr &EtsAbilityRouterMgr::GetInstance()
{
    static EtsAbilityRouterMgr instance;
    return instance;
}

void EtsAbilityRouterMgr::BusinessAbilityFilterCheck(ani_env *env, ani_object filterObj)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "BusinessAbilityFilterCheck called");
    BusinessAbilityFilter filter;
    if (!UnwrapBusinessAbilityFilter(env, filterObj, filter)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Failed to UnwrapBusinessAbilityFilter");
        EtsErrorUtil::ThrowError(env, BusinessErrorAni::CreateCommonError(env, ERROR_PARAM_CHECK_ERROR,
            TYPE_BUSINESS_AIBILITY_FILTER, "BusinessAbilityFilter"));
    }
}

void EtsAbilityRouterMgr::QueryBusinessAbilityInfos(ani_env *env, ani_object filterObj, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "QueryBusinessAbilityInfos called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return;
    }
    GetInstance().OnQueryBusinessAbilityInfos(env, filterObj, callbackObj);
}

void EtsAbilityRouterMgr::OnQueryBusinessAbilityInfos(ani_env *env, ani_object filterObj, ani_object callbackObj)
{
    BusinessAbilityFilter filter;
    if (!UnwrapBusinessAbilityFilter(env, filterObj, filter)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Failed to UnwrapBusinessAbilityFilter");
        return;
    }
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    if (serviceRouterMgr == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Get serviceRouterMgr failed");
        AsyncCallback(env, callbackObj, BusinessErrorAni::CreateCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            QUERY_BUSINESS_ABILITY_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED), nullptr);
        return;
    }
    int32_t funcResult = -1;
    std::vector<BusinessAbilityInfo> businessAbilityInfos;
    auto ret = serviceRouterMgr->QueryBusinessAbilityInfos(filter, businessAbilityInfos, funcResult);
    if (ret == ERR_INVALID_VALUE || ret == ERR_INVALID_DATA) {
        TAG_LOGI(AAFwkTag::SER_ROUTER, "SendRequest failed, error:%{public}d", ret);
        funcResult = ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ret = CommonFunc::ConvertErrCode(funcResult);
    if (ret != NO_ERROR) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "QueryBusinessAbilityInfos failed funcResult : %{public}d", funcResult);
        AsyncCallback(env, callbackObj, BusinessErrorAni::CreateCommonError(env, ret,
            QUERY_BUSINESS_ABILITY_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED), nullptr);
        return;
    }
    ani_object result = ConvertBusinessAbilityInfos(env, businessAbilityInfos);
    AsyncCallback(env, callbackObj, BusinessErrorAni::CreateError(env, static_cast<int32_t>(NO_ERROR), ""), result);
}

void EtsBusinessAbilityRouterInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "EtsBusinessAbilityRouterInit Called.");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "ResetError failed");
    }

    ani_namespace ns;
    status = env->FindNamespace(ETS_DELEGATOR_REGISTRY_NAMESPACE, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "FindNamespace appRecovery failed status: %{public}d", status);
        return;
    }

    std::array kitFunctions = {
        ani_native_function {"nativeQueryBusinessAbilityInfos",
            "L@ohos/app/businessAbilityRouter/businessAbilityRouter/BusinessAbilityFilter;"
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsAbilityRouterMgr::QueryBusinessAbilityInfos)},
        ani_native_function {"nativeBusinessAbilityFilterCheck",
            "L@ohos/app/businessAbilityRouter/businessAbilityRouter/BusinessAbilityFilter;",
            reinterpret_cast<void *>(EtsAbilityRouterMgr::BusinessAbilityFilterCheck)},
            
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Namespace_BindNativeFunctions failed status: %{public}d", status);
    }

    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::SER_ROUTER, "EtsBusinessAbilityRouterInit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "ANI_Constructor start.");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null vm or result");
        return ANI_INVALID_ARGS;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsBusinessAbilityRouterInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::SER_ROUTER, "ANI_Constructor finished");
    return ANI_OK;
}
}
}  // namespace AbilityRuntime
}  // namespace OHOS