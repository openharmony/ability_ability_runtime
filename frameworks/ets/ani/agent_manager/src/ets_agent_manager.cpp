/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ets_agent_manager.h"

#include "ability_business_error.h"
#include "agent_manager_client.h"
#include "ani_common_util.h"
#include "ets_agent_manager_utils.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"

using namespace OHOS::AgentRuntime;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AgentManagerEts {
namespace {
constexpr int32_t INVALID_PARAM = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
constexpr const char* AGENT_MANAGER_SPACE_NAME = "@ohos.app.ability.agentManager.agentManager";
} // namespace

class EtsAgentManager final {
public:
    static ani_object GetAllAgentCards(ani_env *env);
    static ani_object GetAgentCardsByBundleName(ani_env *env, ani_string aniBundleName);
    static ani_object GetAgentCardByUrl(ani_env *env, ani_string aniBundleName, ani_string aniUrl);
};

ani_object EtsAgentManager::GetAllAgentCards(ani_env *env)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "GetAllAgentCards");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "env is null");
        return nullptr;
    }

    std::vector<AgentCard> cards;
    int32_t ret = AgentManagerClient::GetInstance().GetAllAgentCards(cards);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "get all cards failed: %{public}d", ret);
        AbilityRuntime::EtsErrorUtil::ThrowErrorByNativeErr(env, ret);
        return nullptr;
    }
    return CreateEtsAgentCardArray(env, cards);
}

ani_object EtsAgentManager::GetAgentCardsByBundleName(ani_env *env, ani_string aniBundleName)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "GetAgentCardsByBundleName");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "env is null");
        return nullptr;
    }
    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "param bundlename err");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, INVALID_PARAM, "Parameter error. Convert bundleName fail.");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::SER_ROUTER, "bundleName: %{public}s", bundleName.c_str());

    std::vector<AgentCard> cards;
    int32_t ret = AgentManagerClient::GetInstance().GetAgentCardsByBundleName(bundleName, cards);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "get cards by bundle failed: %{public}d", ret);
        AbilityRuntime::EtsErrorUtil::ThrowErrorByNativeErr(env, ret);
        return nullptr;
    }
    return CreateEtsAgentCardArray(env, cards);
}

ani_object EtsAgentManager::GetAgentCardByUrl(ani_env *env, ani_string aniBundleName, ani_string aniUrl)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "GetAgentCardByUrl");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "env is null");
        return nullptr;
    }
    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "param bundlename err");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, INVALID_PARAM, "Parameter error. Convert bundleName fail.");
        return nullptr;
    }
    std::string url;
    if (!AppExecFwk::GetStdString(env, aniUrl, url)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "param url err");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, INVALID_PARAM, "Parameter error. Convert url fail.");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::SER_ROUTER, "bundleName: %{public}s, url: %{public}s", bundleName.c_str(), url.c_str());

    AgentCard card;
    int32_t ret = AgentManagerClient::GetInstance().GetAgentCardByUrl(bundleName, url, card);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "get card by url failed: %{public}d", ret);
        AbilityRuntime::EtsErrorUtil::ThrowErrorByNativeErr(env, ret);
        return nullptr;
    }
    return CreateEtsAgentCard(env, card);
}

void EtsAgentManagerRegistryInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "EtsAgentManagerRegistryInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "ResetError failed");
    }
    ani_namespace ns;
    status = env->FindNamespace(AGENT_MANAGER_SPACE_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "FindNamespace agentManager failed status : %{public}d", status);
        return;
    }
    std::array kitFunctions = {
        ani_native_function{ "nativeGetAllAgentCards", ":C{std.core.Array}",
            reinterpret_cast<void *>(EtsAgentManager::GetAllAgentCards) },
        ani_native_function{ "nativeGetAgentCardsByBundleName", "C{std.core.String}:C{std.core.Array}",
            reinterpret_cast<void *>(EtsAgentManager::GetAgentCardsByBundleName) },
        ani_native_function{ "nativeGetAgentCardByUrl",
            "C{std.core.String}C{std.core.String}:C{@ohos.app.ability.AgentCard.AgentCard}",
            reinterpret_cast<void *>(EtsAgentManager::GetAgentCardByUrl) },
	};
    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::SER_ROUTER, "EtsAgentManagerRegistryInit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "in AgentManagerEts.ANI_Constructor");
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
    EtsAgentManagerRegistryInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::SER_ROUTER, "AgentManagerEts.ANI_Constructor finished");
    return ANI_OK;
}
}  // extern "C"
}  // namespace AgentManagerEts
}  // namespace OHOS
