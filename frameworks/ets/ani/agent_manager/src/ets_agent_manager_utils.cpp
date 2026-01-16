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

#include "ets_agent_manager_utils.h"

#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AgentRuntime;

namespace OHOS {
namespace AgentManagerEts {
namespace {
constexpr const char *CLASSNAME_ARRAY = "std.core.Array";
constexpr const char *PROVIDER_IMPL_CLASS_NAME = "@ohos.app.ability.AgentCard.ProviderImpl";
constexpr const char *CAPABILITIES_IMPL_CLASS_NAME = "@ohos.app.ability.AgentCard.CapabilitiesImpl";
constexpr const char *AUTHENTICATION_IMPL_CLASS_NAME = "@ohos.app.ability.AgentCard.AuthenticationImpl";
constexpr const char *SKILL_IMPL_CLASS_NAME = "@ohos.app.ability.AgentCard.SkillImpl";
constexpr const char *AGENT_CARD_IMPL_CLASS_NAME = "@ohos.app.ability.AgentCard.AgentCardImpl";
}  // namespace

ani_object CreateEtsProvider(ani_env *env, const Provider &provider)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(PROVIDER_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find clss %{public}s failed: %{public}d", PROVIDER_IMPL_CLASS_NAME, status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor method failed: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "new object failed: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(
        object, "organization", GetAniString(env, provider.organization));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "url", GetAniString(env, provider.url));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CreateEtsCapabilities(ani_env *env, const Capabilities &capabilities)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CAPABILITIES_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find clss %{public}s failed: %{public}d",
            CAPABILITIES_IMPL_CLASS_NAME, status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor method failed: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "new object failed: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Boolean(object, "streaming", capabilities.streaming);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "pushNotifications",
        CreateBoolean(env, static_cast<ani_boolean>(capabilities.pushNotifications)));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "stateTransitionHistory",
        CreateBoolean(env, static_cast<ani_boolean>(capabilities.stateTransitionHistory)));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CreateEtsAuthentication(ani_env *env, const Authentication &authentication)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(AUTHENTICATION_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find clss %{public}s failed: %{public}d",
            AUTHENTICATION_IMPL_CLASS_NAME, status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor method failed: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "new object failed: %{public}d", status);
        return nullptr;
    }
    if (authentication.schemes.size() > 0 && !SetStringArrayProperty(env, object, "schemes", authentication.schemes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set schemes failed");
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "credentials", GetAniString(env, authentication.credentials));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CreateEtsSkill(ani_env *env, const Skill &skill)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(SKILL_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find clss %{public}s failed: %{public}d", SKILL_IMPL_CLASS_NAME, status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor method failed: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "new object failed: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "id", GetAniString(env, skill.id));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "name", GetAniString(env, skill.name));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "description", GetAniString(env, skill.description));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    if (skill.tags.size() > 0 && !SetStringArrayProperty(env, object, "tags", skill.tags)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set tags failed");
        return nullptr;
    }
    if (skill.examples.size() > 0 && !SetStringArrayProperty(env, object, "examples", skill.examples)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set examples failed");
        return nullptr;
    }
    if (skill.inputModes.size() > 0 && !SetStringArrayProperty(env, object, "inputModes", skill.inputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set inputModes failed");
        return nullptr;
    }
    if (skill.outputModes.size() > 0 && !SetStringArrayProperty(env, object, "outputModes", skill.outputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set outputModes failed");
        return nullptr;
    }
    return object;
}

ani_object CreateEtsSkillArray(ani_env *env, const std::vector<std::shared_ptr<Skill>> &skills)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }

    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;
    if ((status = env->FindClass(CLASSNAME_ARRAY, &arrayCls)) != ANI_OK || arrayCls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find array class failed: %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor;
    if ((env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) != ANI_OK || arrayCtor == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor failed: %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj;
    if ((status = env->Object_New(arrayCls, arrayCtor, &arrayObj, skills.size())) != ANI_OK || arrayObj == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Object_New array failed: %{public}d", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto skill : skills) {
        if (skill == nullptr) {
            continue;
        }
        ani_object aniSkill = CreateEtsSkill(env, *skill);
        if (aniSkill == nullptr) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "null aniSkill");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniSkill);
        if (status != ANI_OK) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "Object_CallMethodByName_Void failed: %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}

ani_object CreateEtsAgentCard(ani_env *env, const AgentCard &card)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(AGENT_CARD_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find clss %{public}s failed: %{public}d", AGENT_CARD_IMPL_CLASS_NAME, status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor method failed: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "new object failed: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "bundleName", GetAniString(env, card.bundleName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "moduleName", GetAniString(env, card.moduleName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "abilityName", GetAniString(env, card.abilityName));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Int(object, "appIndex", card.appIndex);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "name", GetAniString(env, card.name));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "description", GetAniString(env, card.description));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "url", GetAniString(env, card.url));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "version", GetAniString(env, card.version));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "documentationUrl", GetAniString(env, card.documentationUrl));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
        return nullptr;
    }
    if (card.provider) {
        status = env->Object_SetPropertyByName_Ref(object, "provider", CreateEtsProvider(env, *(card.provider)));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "set provider failed:%{public}d", status);
            return nullptr;
        }
    }
    if (card.capabilities) {
        status = env->Object_SetPropertyByName_Ref(object, "capabilities",
            CreateEtsCapabilities(env, *(card.capabilities)));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
            return nullptr;
        }
    }
    if (card.authentication) {
        status = env->Object_SetPropertyByName_Ref(object, "authentication",
            CreateEtsAuthentication(env, *(card.authentication)));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
            return nullptr;
        }
    }
    if (card.defaultInputModes.size() > 0 &&
        !SetStringArrayProperty(env, object, "defaultInputModes", card.defaultInputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set defaultInputModes failed");
        return nullptr;
    }
    if (card.defaultOutputModes.size() > 0 &&
        !SetStringArrayProperty(env, object, "defaultOutputModes", card.defaultOutputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "set defaultOutputModes failed");
        return nullptr;
    }
    if (card.skills.size() > 0) {
        status = env->Object_SetPropertyByName_Ref(object, "skills", CreateEtsSkillArray(env, card.skills));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "failed status:%{public}d", status);
            return nullptr;
        }
    }
    return object;
}

ani_object CreateEtsAgentCardArray(ani_env *env, const std::vector<AgentCard> &cards)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null env");
        return nullptr;
    }

    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;
    if ((status = env->FindClass(CLASSNAME_ARRAY, &arrayCls)) != ANI_OK || arrayCls == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find array class failed: %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor;
    if ((env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) != ANI_OK || arrayCtor == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "find ctor failed: %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj;
    if ((status = env->Object_New(arrayCls, arrayCtor, &arrayObj, cards.size())) != ANI_OK || arrayObj == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Object_New array failed: %{public}d", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (const auto &card : cards) {
        ani_object aniCard = CreateEtsAgentCard(env, card);
        if (aniCard == nullptr) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "null aniCard");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniCard);
        if (status != ANI_OK) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "Object_CallMethodByName_Void failed: %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}
} // namespace AgentManagerEts
} // namespace OHOS
