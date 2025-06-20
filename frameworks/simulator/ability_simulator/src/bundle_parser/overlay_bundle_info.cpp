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
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* BUNDLE_OVERLAY_BUNDLE_NAME = "bundleName";
const char* BUNDLE_OVERLAY_BUNDLE_DIR = "bundleDir";
const char* BUNDLE_OVERLAY_BUNDLE_STATE = "state";
const char* BUNDLE_OVERLAY_BUNDLE_PRIORITY = "priority";
} // namespace

bool to_json(cJSON *&jsonObject, const OverlayBundleInfo &overlayBundleInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, BUNDLE_OVERLAY_BUNDLE_NAME, overlayBundleInfo.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, BUNDLE_OVERLAY_BUNDLE_DIR, overlayBundleInfo.bundleDir.c_str());
    cJSON_AddNumberToObject(jsonObject, BUNDLE_OVERLAY_BUNDLE_STATE, static_cast<double>(overlayBundleInfo.state));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_OVERLAY_BUNDLE_PRIORITY,
        static_cast<double>(overlayBundleInfo.priority));
    return true;
}

void from_json(const cJSON *jsonObject, OverlayBundleInfo &overlayBundleInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, BUNDLE_OVERLAY_BUNDLE_NAME, overlayBundleInfo.bundleName, true, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_OVERLAY_BUNDLE_DIR, overlayBundleInfo.bundleDir, true, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_OVERLAY_BUNDLE_STATE, overlayBundleInfo.state, true, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_OVERLAY_BUNDLE_PRIORITY, overlayBundleInfo.priority, true, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "overlayBundleInfo from_json error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS
