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

#include "js_insight_intent_decorator.h"

#include "hilog_tag_wrapper.h"
#include "napi_common_execute_param.h"
#include "napi_common_util.h"
#include "native_engine/native_value.h"

#include <mutex>

namespace OHOS {
namespace AbilityRuntime {
class JsInsightIntentDecorator {
public:
    JsInsightIntentDecorator() = default;
    ~JsInsightIntentDecorator() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        TAG_LOGI(AAFwkTag::INTENT, "finalizer");
        std::unique_ptr<JsInsightIntentDecorator>(static_cast<JsInsightIntentDecorator*>(data));
    }
};

static napi_status SetEnumItem(napi_env env, napi_value napiObject, const char* name, const char* value)
{
    napi_status status;
    napi_value itemName;
    napi_value itemValue;

    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName), status);
    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &itemValue), status);

    NAPI_CALL_BASE(env, status = napi_set_property(env, napiObject, itemName, itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, napiObject, itemValue, itemName), status);

    return napi_ok;
}

static napi_value InitLinkParamCategory(napi_env env)
{
    napi_value napiObject;
    NAPI_CALL(env, napi_create_object(env, &napiObject));

    NAPI_CALL(env, SetEnumItem(env, napiObject, "LINK", "link"));
    NAPI_CALL(env, SetEnumItem(env, napiObject, "WANT", "want"));

    return napiObject;
}

napi_value JsInsightIntentDecoratorInit(napi_env env, napi_value exportObj)
{
    TAG_LOGD(AAFwkTag::INTENT, "JsInsightIntentDecoratorInit");
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env or exportObj");
        return nullptr;
    }

    std::unique_ptr<JsInsightIntentDecorator> jsIntentDecorator = std::make_unique<JsInsightIntentDecorator>();
    auto res = napi_wrap(
        env, exportObj, jsIntentDecorator.release(), JsInsightIntentDecorator::Finalizer, nullptr, nullptr);
    if (res != napi_ok) {
        TAG_LOGE(AAFwkTag::INTENT, "wrap failed: %{public}d", res);
        return nullptr;
    }

    napi_value linkParamCategory = InitLinkParamCategory(env);
    NAPI_ASSERT(env, linkParamCategory != nullptr, "failed to create link param category");

    napi_property_descriptor exportObjs[] = {
        DECLARE_NAPI_PROPERTY("LinkParamCategory", linkParamCategory),
    };
    napi_status status = napi_define_properties(env, exportObj, sizeof(exportObjs) / sizeof(exportObjs[0]), exportObjs);
    NAPI_ASSERT(env, status == napi_ok, "failed to define properties");
    return CreateJsUndefined(env);
}
} // namespace AbilityRuntime
} // namespace OHOS
