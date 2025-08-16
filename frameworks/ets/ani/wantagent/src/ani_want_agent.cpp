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

#include "ani_want_agent.h"

#include "ability_runtime_error_util.h"
#include "ani_common_start_options.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_common_want_agent.h"
#include "ani_enum_convert.h"
#include "hilog_tag_wrapper.h"
#include "start_options.h"
#include "want_agent_helper.h"
#include "tokenid_kit.h"

using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace {
constexpr int32_t ERR_NOT_OK = -1;
constexpr int32_t BUSINESS_ERROR_CODE_OK = 0;
constexpr int32_t PARAMETER_ERROR = -1;
constexpr const char* COMPLETE_DATA_IMPL_CLASS_NAME = "L@ohos/app/ability/wantAgent/wantAgent/CompleteDataImpl;";
constexpr const char* WANT_AGENT_NAMESPACE = "L@ohos/app/ability/wantAgent/wantAgent;";
constexpr const char* CLEANER_CLASS = "L@ohos/app/ability/wantAgent/wantAgent/Cleaner;";

bool CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Non-system app forbidden to call");
        return false;
    }
    return true;
}
} // namespace

TriggerCompleteCallBack::TriggerCompleteCallBack()
{}

TriggerCompleteCallBack::~TriggerCompleteCallBack()
{}

void TriggerCompleteCallBack::SetCallbackInfo(ani_vm *vm, ani_ref call)
{
    triggerCompleteInfo_.vm = vm;
    triggerCompleteInfo_.call = call;
}

void TriggerCompleteCallBack::SetWantAgentInstance(std::shared_ptr<WantAgent> wantAgent)
{
    triggerCompleteInfo_.wantAgent = wantAgent;
}

void OnSendFinishedCallback(TriggerReceiveDataWorker *dataWorker)
{
    if (dataWorker == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null dataWorker");
        return;
    }
    ani_vm *etsVm = dataWorker->vm;
    if (etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null etsVm");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = etsVm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetEnv failed status: %{public}d, or null env", status);
        return;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(COMPLETE_DATA_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "FindClass failed status: %{public}d, or null class", status);
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Class_FindMethod failed status: %{public}d, or null method", status);
        return;
    }
    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Object_New failed status: %{public}d, or null object", status);
        return;
    }
    env->Object_SetPropertyByName_Ref(object, "info", WrapWantAgent(env, dataWorker->wantAgent));
    env->Object_SetPropertyByName_Ref(object, "want", WrapWant(env, dataWorker->want));
    env->Object_SetPropertyByName_Double(object, "finalCode", static_cast<ani_double>(dataWorker->resultCode));
    env->Object_SetPropertyByName_Ref(object, "finalData", GetAniString(env, dataWorker->resultData));
    env->Object_SetPropertyByName_Ref(object, "extraInfo", WrapWantParams(env, dataWorker->resultExtras));

    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    AsyncCallback(env, reinterpret_cast<ani_object>(dataWorker->call), error, object);
    env->GlobalReference_Delete(dataWorker->call);
}

void TriggerCompleteCallBack::OnSendFinished(
    const AAFwk::Want &want, int resultCode, const std::string &resultData, const AAFwk::WantParams &resultExtras)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "OnSendFinished");
    if (triggerCompleteInfo_.call == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null CallBack");
        return;
    }
    TriggerReceiveDataWorker* dataWorker = new (std::nothrow) TriggerReceiveDataWorker();
    if (dataWorker == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null dataWorker");
        return;
    }
    dataWorker->want = want;
    dataWorker->resultCode = resultCode;
    dataWorker->resultData = resultData;
    dataWorker->resultExtras = resultExtras;
    dataWorker->vm = triggerCompleteInfo_.vm;
    dataWorker->call = triggerCompleteInfo_.call;
    if (triggerCompleteInfo_.wantAgent != nullptr) {
        dataWorker->wantAgent = new (std::nothrow) WantAgent(triggerCompleteInfo_.wantAgent->GetPendingWant());
        if (dataWorker->wantAgent == nullptr) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "new WantAgent(triggerCompleteInfo_.wantAgent->GetPendingWant()) failed");
            return;
        }
    }
    OnSendFinishedCallback(dataWorker);
    if (dataWorker != nullptr) {
        delete dataWorker;
        dataWorker = nullptr;
    }
}

EtsWantAgent& EtsWantAgent::GetInstance()
{
    static EtsWantAgent instance;
    return instance;
}

void EtsWantAgent::GetBundleName(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetBundleName called");
    GetInstance().OnGetBundleName(env, agent, call);
};

void EtsWantAgent::GetUid(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetUid called");
    GetInstance().OnGetUid(env, agent, call);
};

void EtsWantAgent::Cancel(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "Cancel called");
    GetInstance().OnCancel(env, agent, call);
};

void EtsWantAgent::Equal(ani_env *env, ani_object agent, ani_object otherAgent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "Equal called");
    GetInstance().OnEqual(env, agent, otherAgent, call);
};

void EtsWantAgent::GetWant(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetWant called");
    GetInstance().OnGetWant(env, agent, call);
};

void EtsWantAgent::GetOperationType(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetOperationType called");
    GetInstance().OnGetOperationType(env, agent, call);
};

void EtsWantAgent::Trigger(ani_env *env, ani_object agent, ani_object triggerInfoObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "Trigger called");
    GetInstance().OnTrigger(env, agent, triggerInfoObj, call);
};

void EtsWantAgent::GetWantAgent(ani_env *env, ani_object info, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetWantAgent called");
    GetInstance().OnGetWantAgent(env, info, call);
}

void EtsWantAgent::Clean(ani_env *env, ani_object object)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "Clean called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    ani_long ptr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "ptr", &ptr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "ptr GetField status: %{public}d", status);
        return;
    }
    if (ptr != 0) {
        delete reinterpret_cast<WantAgent *>(ptr);
    }
}

void EtsWantAgent::OnGetBundleName(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    std::string bundleName = "";
    ErrCode resultCode = WantAgentHelper::GetBundleName(wantAgent, bundleName);
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (resultCode != ERR_OK) {
        error = EtsErrorUtil::CreateError(env, resultCode, AbilityRuntimeErrorUtil::GetErrMessage(resultCode));
    }
    ani_string aniBundleName = GetAniString(env, bundleName);
    AsyncCallback(env, call, error, reinterpret_cast<ani_object>(aniBundleName));
}

void EtsWantAgent::OnGetUid(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    int uid = -1;
    ErrCode resultCode = WantAgentHelper::GetUid(wantAgent, uid);
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (resultCode != ERR_OK) {
        error = EtsErrorUtil::CreateError(env, resultCode, AbilityRuntimeErrorUtil::GetErrMessage(resultCode));
    }
    AsyncCallback(env, call, error, CreateDouble(env, static_cast<ani_double>(uid)));
}

void EtsWantAgent::OnCancel(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    ErrCode resultCode = WantAgentHelper::Cancel(wantAgent);
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (resultCode != NO_ERROR) {
        error = EtsErrorUtil::CreateError(env, resultCode, AbilityRuntimeErrorUtil::GetErrMessage(resultCode));
    }
    AsyncCallback(env, call, error, nullptr);
}

void EtsWantAgent::OnEqual(ani_env *env, ani_object agent, ani_object otherAgent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgentFirst = nullptr;
    WantAgent* pWantAgentSecond = nullptr;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgentFirst));
    UnwrapWantAgent(env, otherAgent, reinterpret_cast<void **>(&pWantAgentSecond));
    if (pWantAgentFirst == nullptr || pWantAgentSecond == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null pWantAgentFirst or pWantAgentSecond");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<WantAgent> wantAgentFirst = std::make_shared<WantAgent>(*pWantAgentFirst);
    std::shared_ptr<WantAgent> wantAgentSecond = std::make_shared<WantAgent>(*pWantAgentSecond);
    ErrCode resultCode = WantAgentHelper::IsEquals(wantAgentFirst, wantAgentSecond);
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    bool ret = false;
    if (resultCode == ERR_NOT_OK) {
        ret = false;
    } else if (resultCode == ERR_OK) {
        ret = true;
    } else {
        error = EtsErrorUtil::CreateError(env, resultCode, AbilityRuntimeErrorUtil::GetErrMessage(resultCode));
    }
    AsyncCallback(env, call, error, CreateBoolean(env, static_cast<ani_boolean>(ret)));
}

void EtsWantAgent::OnGetWant(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    if (!CheckCallerIsSystemApp()) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Non-system app");
        EtsErrorUtil::ThrowError(env, ERR_ABILITY_RUNTIME_NOT_SYSTEM_APP,
            AbilityRuntimeErrorUtil::GetErrMessage(ERR_ABILITY_RUNTIME_NOT_SYSTEM_APP));
        return;
    }
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    std::shared_ptr<Want> want = std::make_shared<Want>();
    auto retCode = WantAgentHelper::GetWant(wantAgent, want);
    ani_object wantAniObj = nullptr;
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (retCode != NO_ERROR) {
        error = EtsErrorUtil::CreateError(env, retCode, AbilityRuntimeErrorUtil::GetErrMessage(retCode));
        wantAniObj = WrapWant(env, AAFwk::Want());
    } else {
        wantAniObj = WrapWant(env, *want);
    }
    AsyncCallback(env, call, error, wantAniObj);
}

void EtsWantAgent::OnGetOperationType(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    int32_t operType = NO_ERROR;
    int32_t retCode = NO_ERROR;
    retCode = WantAgentHelper::GetType(wantAgent, operType);
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (retCode != NO_ERROR) {
        error = EtsErrorUtil::CreateError(env, retCode, AbilityRuntimeErrorUtil::GetErrMessage(retCode));
    }
    AsyncCallback(env, call, error, CreateDouble(env, static_cast<ani_double>(operType)));
}

int32_t EtsWantAgent::GetWantAgentParam(ani_env *env, ani_object info, WantAgentParams &params)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetWantAgentParam called");
    ani_ref wantsRef = nullptr;
    ani_status status = env->Object_GetPropertyByName_Ref(info, "wants", &wantsRef);
    if (status != ANI_OK || wantsRef == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "wants GetProperty status: %{public}d, or null wantsRef", status);
        return PARAMETER_ERROR;
    }
    ani_array_ref wantsArr = reinterpret_cast<ani_array_ref>(wantsRef);
    ani_size length = 0;
    if ((status = env->Array_GetLength(wantsArr, &length)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "wants Array_GetLength failed status: %{public}d", status);
        return PARAMETER_ERROR;
    }
    for (size_t i = 0; i < length; i++) {
        ani_ref wantRef = nullptr;
        if ((status = env->Array_Get_Ref(wantsArr, i, &wantRef)) != ANI_OK || wantRef == nullptr) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "Array_Get_Ref failed status: %{public}d, or null wantRef", status);
            return PARAMETER_ERROR;
        }
        std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
        if (!UnwrapWant(env, reinterpret_cast<ani_object>(wantRef), *want)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "UnwrapWant  failed");
            return PARAMETER_ERROR;
        }
        params.wants.emplace_back(want);
    }

    ani_boolean isUndefined = true;
    ani_ref actionTypeRef = nullptr;
    if (!GetPropertyRef(env, info, "actionType", actionTypeRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "actionType GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (!isUndefined) {
        AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
            env, reinterpret_cast<ani_enum_item>(actionTypeRef), params.operationType);
    }

    ani_double dRequestCode = 0.0;
    if ((status = env->Object_GetPropertyByName_Double(info, "requestCode", &dRequestCode)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "requestCode GetProperty failed status: %{public}d", status);
        return PARAMETER_ERROR;
    }
    params.requestCode = dRequestCode;

    ani_ref actionFlagsRef = nullptr;
    if (!GetPropertyRef(env, info, "actionFlags", actionFlagsRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "actionFlags GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (!isUndefined) {
        ani_array_ref actionFlagsArr = reinterpret_cast<ani_array_ref>(actionFlagsRef);
        ani_size actionFlagsLen = 0;
        if ((status = env->Array_GetLength(actionFlagsArr, &actionFlagsLen)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "Array_GetLength failed status: %{public}d", status);
            return PARAMETER_ERROR;
        }
        for (size_t i = 0; i < actionFlagsLen; i++) {
            ani_ref actionFlagRef = nullptr;
            if ((status = env->Array_Get_Ref(actionFlagsArr, i, &actionFlagRef)) != ANI_OK ||
                actionFlagRef == nullptr) {
                TAG_LOGE(AAFwkTag::WANTAGENT, "Array_Get_Ref failed status: %{public}d, or null actionFlagRef", status);
                return PARAMETER_ERROR;
            }
            int32_t actionFlag = 0;
            AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(
                env, reinterpret_cast<ani_object>(actionFlagRef), actionFlag);
            params.wantAgentFlags.emplace_back(static_cast<WantAgentConstant::Flags>(actionFlag));
        }
    }

    ani_ref extraInfoRef = nullptr;
    if (!GetPropertyRef(env, info, "extraInfos", extraInfoRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "extraInfos GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (isUndefined) {
        if (!GetPropertyRef(env, info, "extraInfo", extraInfoRef, isUndefined)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "extraInfo GetPropertyRef failed");
            return PARAMETER_ERROR;
        }
    }
    if (!isUndefined) {
        if (!UnwrapWantParams(env, extraInfoRef, params.extraInfo)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "Convert extraInfo failed");
            return PARAMETER_ERROR;
        }
    }
    return BUSINESS_ERROR_CODE_OK;
}

void EtsWantAgent::OnTrigger(ani_env *env, ani_object agent, ani_object triggerInfoObj, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    TriggerInfo triggerInfo;
    int32_t ret = GetTriggerInfo(env, triggerInfoObj, triggerInfo);
    if (ret != BUSINESS_ERROR_CODE_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Get trigger info error");
        EtsErrorUtil::ThrowInvalidParamError(env, "Get trigger info error. TriggerInfo must be a TriggerInfo.");
        return;
    }
    ani_vm *etsVm = nullptr;
    ani_status status = env->GetVM(&etsVm);
    if (status != ANI_OK || etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetVM failed status: %{public}d, or null etsVm", status);
        return;
    }
    ani_boolean isUndefined = true;
    if ((status = env->Reference_IsUndefined(call, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Reference_IsUndefined failed status: %{public}d", status);
        return;
    }
    ani_ref callbackRef = nullptr;
    if (!isUndefined) {
        if ((status = env->GlobalReference_Create(call, &callbackRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "GlobalReference_Create failed status: %{public}d", status);
            return;
        }
    }
    auto triggerObj = std::make_shared<TriggerCompleteCallBack>();
    triggerObj->SetCallbackInfo(etsVm, callbackRef);
    triggerObj->SetWantAgentInstance(std::make_shared<WantAgent>(pWantAgent->GetPendingWant()));
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    sptr<CompletedDispatcher> completedData;
    WantAgentHelper::TriggerWantAgent(wantAgent, triggerObj, triggerInfo, completedData, nullptr);
}

int32_t EtsWantAgent::GetTriggerInfo(ani_env *env, ani_object triggerInfoObj, TriggerInfo &triggerInfo)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "GetTriggerInfo called");
    ani_double dCode = 0.0;
    ani_status status = env->Object_GetPropertyByName_Double(triggerInfoObj, "code", &dCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "code GetProperty failed status: %{public}d", status);
        return ERR_NOT_OK;
    }
    const int32_t code = static_cast<int32_t>(dCode);

    ani_ref wantRef = nullptr;
    ani_boolean isUndefined = true;
    std::shared_ptr<AAFwk::Want> want = nullptr;
    if (!GetPropertyRef(env, triggerInfoObj, "want", wantRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return ERR_NOT_OK;
    }
    if (!isUndefined) {
        want = std::make_shared<AAFwk::Want>();
        if (!UnwrapWant(env, reinterpret_cast<ani_object>(wantRef), *want)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "UnwrapWant failed");
            return ERR_NOT_OK;
        }
    }

    std::string permission = "";
    ani_ref permissionRef = nullptr;
    if (!GetPropertyRef(env, triggerInfoObj, "permission", permissionRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return ERR_NOT_OK;
    }
    if (!isUndefined && !GetStdString(env, reinterpret_cast<ani_string>(permissionRef), permission)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Failed to get permission string from permissionRef");
        return ERR_NOT_OK;
    }

    ani_ref extraInfoRef = nullptr;
    if (!GetPropertyRef(env, triggerInfoObj, "extraInfos", extraInfoRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return ERR_NOT_OK;
    }
    if (isUndefined) {
        if (!GetPropertyRef(env, triggerInfoObj, "extraInfo", extraInfoRef, isUndefined)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
            return ERR_NOT_OK;
        }
    }
    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (!isUndefined) {
        extraInfo = std::make_shared<AAFwk::WantParams>();
        if (!UnwrapWantParams(env, extraInfoRef, *extraInfo)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "Convert extraInfo failed");
            return ERR_NOT_OK;
        }
    }

    ani_ref startOptionsRef = nullptr;
    if (!GetPropertyRef(env, triggerInfoObj, "startOptions", startOptionsRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return ERR_NOT_OK;
    }
    std::shared_ptr<AAFwk::StartOptions> startOptions = nullptr;
    if (!isUndefined) {
        if (!CheckCallerIsSystemApp()) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "Non-system app");
            EtsErrorUtil::ThrowError(env, ERR_ABILITY_RUNTIME_NOT_SYSTEM_APP,
                AbilityRuntimeErrorUtil::GetErrMessage(ERR_ABILITY_RUNTIME_NOT_SYSTEM_APP));
            return ERR_NOT_OK;
        }
        startOptions = std::make_shared<AAFwk::StartOptions>();
        if (!UnwrapStartOptions(env, reinterpret_cast<ani_object>(startOptionsRef), *startOptions)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "UnwrapStartOptions failed");
            return ERR_NOT_OK;
        }
    }

    TriggerInfo triggerInfoData(permission, extraInfo, want, startOptions, code);
    triggerInfo = triggerInfoData;
    return BUSINESS_ERROR_CODE_OK;
}

void EtsWantAgent::OnGetWantAgent(ani_env *env, ani_object info, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    std::shared_ptr<WantAgentParams> parasobj = std::make_shared<WantAgentParams>();
    int32_t ret = GetWantAgentParam(env, info, *parasobj);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Failed to get wantAgent parameter. Agent must be a WantAgent.");
        EtsErrorUtil::ThrowInvalidParamError(env, "Failed to get wantAgent parameter. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>(parasobj->extraInfo);
    WantAgentInfo wantAgentInfo(parasobj->requestCode,
                                static_cast<WantAgentConstant::OperationType>(parasobj->operationType),
                                parasobj->wantAgentFlags,
                                parasobj->wants,
                                extraInfo);
    auto context = OHOS::AbilityRuntime::Context::GetApplicationContext();
    std::shared_ptr<WantAgent> wantAgent = nullptr;
    ErrCode result = WantAgentHelper::GetWantAgent(context, wantAgentInfo, wantAgent);
    ani_object error = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    ani_object retObj = CreateLong(env, ERR_NOT_OK);
    if (result != NO_ERROR) {
        error = EtsErrorUtil::CreateError(env, result, AbilityRuntimeErrorUtil::GetErrMessage(result));
        AsyncCallback(env, call, error, retObj);
        return;
    }
    if (wantAgent == nullptr) {
        result = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        error = EtsErrorUtil::CreateError(env, result, AbilityRuntimeErrorUtil::GetErrMessage(result));
        AsyncCallback(env, call, error, retObj);
        return;
    }
    WantAgent *pWantAgent = new (std::nothrow) WantAgent(wantAgent->GetPendingWant());
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null pWantAgent");
        result = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        error = EtsErrorUtil::CreateError(env, result, AbilityRuntimeErrorUtil::GetErrMessage(result));
        AsyncCallback(env, call, error, retObj);
    } else {
        retObj = WrapWantAgent(env, pWantAgent);
        if (retObj == nullptr) {
            delete pWantAgent;
            pWantAgent = nullptr;
        }
        AsyncCallback(env, call, error, retObj);
    }
}

ani_status BindNativeFunctions(ani_env *env)
{
    ani_namespace ns = nullptr;
    ani_status status = env->FindNamespace(WANT_AGENT_NAMESPACE, &ns);
    if (status != ANI_OK || ns == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "FindNamespace failed status: %{public}d, or null ns", status);
        return status;
    }
    std::array functions = {
        ani_native_function { "nativeGetBundleName", nullptr, reinterpret_cast<void *>(EtsWantAgent::GetBundleName) },
        ani_native_function { "nativeGetUid", nullptr, reinterpret_cast<void *>(EtsWantAgent::GetUid) },
        ani_native_function {
            "nativeGetOperationType", nullptr, reinterpret_cast<void *>(EtsWantAgent::GetOperationType) },
        ani_native_function { "nativeCancel", nullptr, reinterpret_cast<void *>(EtsWantAgent::Cancel) },
        ani_native_function { "nativeEqual", nullptr, reinterpret_cast<void *>(EtsWantAgent::Equal) },
        ani_native_function { "nativeTrigger", nullptr, reinterpret_cast<void *>(EtsWantAgent::Trigger) },
        ani_native_function { "nativeGetWant", nullptr, reinterpret_cast<void *>(EtsWantAgent::GetWant) },
        ani_native_function { "nativeGetWantAgent", nullptr, reinterpret_cast<void *>(EtsWantAgent::GetWantAgent) },
    };
    if ((status = env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Namespace_BindNativeFunctions failed status: %{public}d", status);
        return status;
    }

    ani_class cleanerCls = nullptr;
    if ((status = env->FindClass(CLEANER_CLASS, &cleanerCls)) != ANI_OK || cleanerCls == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Cleaner FindClass failed status: %{public}d, or null cleanerCls", status);
        return status;
    }
    std::array cleanerMethods = {
        ani_native_function {"clean", nullptr, reinterpret_cast<void *>(EtsWantAgent::Clean) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, cleanerMethods.data(), cleanerMethods.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Class_BindNativeMethods failed status: %{public}d", status);
        return status;
    }
    return ANI_OK;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "ANI_Constructor");
    ani_env *env = nullptr;
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null vm");
        return ANI_NOT_FOUND;
    }
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetEnv failed status: %{public}d, or null env", status);
        return status;
    }
    if ((status = BindNativeFunctions(env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "BindNativeFunctions failed status: %{public}d", status);
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace OHOS
