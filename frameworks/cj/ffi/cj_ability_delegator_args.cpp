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

#include "cj_ability_delegator_args.h"
#include "ability_delegator_registry.h"
#include "hilog_tag_wrapper.h"
#include "cj_utils_ffi.h"

namespace OHOS {
namespace AbilityDelegatorArgsCJ {
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;

const int32_t INVALID_ARG = -1;

std::string CJAbilityDelegatorArgs::GetTestBundleName()
{
    return delegatorArgs_->GetTestBundleName();
}

std::map<std::string, std::string> CJAbilityDelegatorArgs::GetTestParam()
{
    return delegatorArgs_->GetTestParam();
}

std::string CJAbilityDelegatorArgs::GetTestCaseName()
{
    return delegatorArgs_->GetTestCaseName();
}

std::string CJAbilityDelegatorArgs::GetTestRunnerClassName()
{
    return delegatorArgs_->GetTestRunnerClassName();
}

extern "C" {
int64_t FfiAbilityDelegatorRegistryGetArguments()
{
    auto delegatorArgs = OHOS::AppExecFwk::AbilityDelegatorRegistry::GetArguments();
    if (delegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null cj delegatorArgs");
        return INVALID_ARG;
    }
    auto cjDelegatorArgs = FFI::FFIData::Create<CJAbilityDelegatorArgs>(delegatorArgs);
    if (cjDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "cj delegatorArgs is null.");
        return INVALID_ARG;
    }
    return cjDelegatorArgs->GetID();
}

char* FfiAbilityDelegatorArgsGetTestBundleName(int64_t id, int32_t *errCode)
{
    auto cjDelegatorArgs = FFI::FFIData::GetData<CJAbilityDelegatorArgs>(id);
    if (cjDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null cj delegatorArgs");
        *errCode = INVALID_ARG;
        return nullptr;
    }
    std::string bundleName = cjDelegatorArgs->GetTestBundleName();
    return CreateCStringFromString(bundleName);
}

CRecord FfiAbilityDelegatorArgsGetTestParam(int64_t id, int32_t *errCode)
{
    CRecord ret = { .keys = { .head = nullptr, .size = 0}, .values = { .head = nullptr, .size = 0}};
    auto cjDelegatorArgs = FFI::FFIData::GetData<CJAbilityDelegatorArgs>(id);
    if (cjDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null cj delegatorArgs");
        *errCode = INVALID_ARG;
        return ret;
    }
    std::map<std::string, std::string> params = cjDelegatorArgs->GetTestParam();
    char** keysHead = static_cast<char**>(malloc(sizeof(char*) * params.size()));
    if (keysHead == nullptr) {
        *errCode = INVALID_ARG;
        return ret;
    }
    char** valuesHead = static_cast<char**>(malloc(sizeof(char*) * params.size()));
    if (valuesHead == nullptr) {
        *errCode = INVALID_ARG;
        free(keysHead);
        return ret;
    }
    int64_t i = 0;
    for (auto &param : params) {
        keysHead[i] = CreateCStringFromString(param.first);
        valuesHead[i] = CreateCStringFromString(param.second);
        i++;
    }
    ret.keys.size = params.size();
    ret.keys.head = keysHead;
    ret.values.size = params.size();
    ret.values.head = valuesHead;
    return ret;
}

char* FfiAbilityDelegatorArgsGetTestCaseName(int64_t id, int32_t *errCode)
{
    auto cjDelegatorArgs = FFI::FFIData::GetData<CJAbilityDelegatorArgs>(id);
    if (cjDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null cj delegatorArgs");
        *errCode = INVALID_ARG;
        return nullptr;
    }
    std::string testCaseName = cjDelegatorArgs->GetTestCaseName();
    return CreateCStringFromString(testCaseName);
}

char* FfiAbilityDelegatorArgsGetTestRunnerClassName(int64_t id, int32_t *errCode)
{
    auto cjDelegatorArgs = FFI::FFIData::GetData<CJAbilityDelegatorArgs>(id);
    if (cjDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null cj delegatorArgs");
        *errCode = INVALID_ARG;
        return nullptr;
    }
    std::string testRunnerClassName = cjDelegatorArgs->GetTestRunnerClassName();
    return CreateCStringFromString(testRunnerClassName);
}
}
}
}