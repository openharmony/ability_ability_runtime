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

#include "overlay_bundle_info.h"

#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* BUNDLE_OVERLAY_BUNDLE_NAME = "bundleName";
const char* BUNDLE_OVERLAY_BUNDLE_DIR = "bundleDir";
const char* BUNDLE_OVERLAY_BUNDLE_STATE = "state";
const char* BUNDLE_OVERLAY_BUNDLE_PRIORITY = "priority";
} // namespace

void to_json(nlohmann::json &jsonObject, const OverlayBundleInfo &overlayBundleInfo)
{
    jsonObject = nlohmann::json {
        {BUNDLE_OVERLAY_BUNDLE_NAME, overlayBundleInfo.bundleName},
        {BUNDLE_OVERLAY_BUNDLE_DIR, overlayBundleInfo.bundleDir},
        {BUNDLE_OVERLAY_BUNDLE_STATE, overlayBundleInfo.state},
        {BUNDLE_OVERLAY_BUNDLE_PRIORITY, overlayBundleInfo.priority}
    };
}

void from_json(const nlohmann::json &jsonObject, OverlayBundleInfo &overlayBundleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_NAME,
        overlayBundleInfo.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_DIR,
        overlayBundleInfo.bundleDir,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_STATE,
        overlayBundleInfo.state,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_PRIORITY,
        overlayBundleInfo.priority,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "overlayBundleInfo from_json error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS
