/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_extension_common.h"

#include "hilog_tag_wrapper.h"
#include "cj_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

std::shared_ptr<CJExtensionCommon> CJExtensionCommon::Create(CJUIExtensionObject cjObj)
{
    return std::make_shared<CJExtensionCommon>(cjObj);
}

CJExtensionCommon::CJExtensionCommon(CJUIExtensionObject cjObj)
    : cjObj_(cjObj) {}

void CJExtensionCommon::OnConfigurationUpdated(const std::shared_ptr<AppExecFwk::Configuration> &fullConfig)
{
    TAG_LOGI(AAFwkTag::EXT, "called");
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::EXT, "invalid config");
        return;
    }

    cjObj_.OnConfigurationUpdate(fullConfig);
}

void CJExtensionCommon::OnMemoryLevel(int level)
{
    TAG_LOGD(AAFwkTag::EXT, "called");
    cjObj_.OnMemoryLevel(level);
}
} // namespace AbilityRuntime
} // namespace OHOS
