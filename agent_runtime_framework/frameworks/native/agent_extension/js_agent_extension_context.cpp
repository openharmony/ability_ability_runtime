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


#include <chrono>
#include <cstdint>
#include "ability_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "js_agent_extension_context.h"
#include "js_extension_context.h"
#include "js_error_utils.h"
#include "js_data_struct_converter.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_ability.h"
#include "napi_common_want.h"
#include "napi_common_util.h"
#include "napi_remote_object.h"
#include "napi_common_start_options.h"
#include "start_options.h"
#include "uri.h"

namespace OHOS {
namespace AgentRuntime {
using namespace OHOS::AbilityRuntime;
namespace {
class JsAgentExtensionContext final {
public:
    explicit JsAgentExtensionContext(
        const std::shared_ptr<AgentExtensionContext>& context) : context_(context) {}
    ~JsAgentExtensionContext() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        TAG_LOGD(AAFwkTag::SER_ROUTER, "called");
        std::unique_ptr<JsAgentExtensionContext>(static_cast<JsAgentExtensionContext*>(data));
    }

private:
    std::weak_ptr<AgentExtensionContext> context_;
};
}

napi_value CreateJsAgentExtensionContext(napi_env env, std::shared_ptr<AgentExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "called");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    napi_value object = CreateJsExtensionContext(env, context, abilityInfo);

    std::unique_ptr<JsAgentExtensionContext> jsContext = std::make_unique<JsAgentExtensionContext>(context);
    napi_wrap(env, object, jsContext.release(), JsAgentExtensionContext::Finalizer, nullptr, nullptr);

    std::string type = "AgentExtensionContext";
    napi_set_named_property(env, object, "contextType", CreateJsValue(env, type));

    return object;
}
}
}