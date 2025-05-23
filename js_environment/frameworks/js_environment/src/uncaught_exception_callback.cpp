/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "uncaught_exception_callback.h"

#include <charconv>
#include <string>
#include <sstream>

#include "dfx_symbols.h"
#include "elf_factory.h"
#include "hilog_tag_wrapper.h"
#include "string_printf.h"
#ifdef SUPPORT_GRAPHICS
#include "ui_content.h"
#endif // SUPPORT_GRAPHICS
#include "unwinder.h"
#include "unwinder_config.h"

namespace OHOS {
namespace JsEnv {
constexpr char BACKTRACE[] = "=====================Backtrace========================";
constexpr size_t FLAG_SPLIT_POS = 16;
constexpr size_t FLAG_PC_POS = 4;

std::string NapiUncaughtExceptionCallback::GetNativeStrFromJsTaggedObj(napi_value obj, const char* key)
{
    if (obj == nullptr) {
        TAG_LOGE(AAFwkTag::JSENV, "Failed to get value from key");
        return "";
    }

    napi_value valueStr = nullptr;
    napi_get_named_property(env_, obj, key, &valueStr);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env_, valueStr, &valueType);
    if (valueType != napi_string) {
        TAG_LOGD(AAFwkTag::JSENV, "Failed to convert value from key");
        return "";
    }

    size_t valueStrBufLength = 0;
    napi_get_value_string_utf8(env_, valueStr, nullptr, 0, &valueStrBufLength);
    auto valueCStr = std::make_unique<char[]>(valueStrBufLength + 1);
    size_t valueStrLength = 0;
    napi_get_value_string_utf8(env_, valueStr, valueCStr.get(), valueStrBufLength + 1, &valueStrLength);
    std::string ret(valueCStr.get(), valueStrLength);
    TAG_LOGD(AAFwkTag::JSENV, "GetNativeStrFromJsTaggedObj Success");
    return ret;
}

void NapiUncaughtExceptionCallback::operator()(napi_value obj)
{
    CallbackTask(obj);
}

void NapiUncaughtExceptionCallback::operator()(panda::TryCatch& trycatch)
{
    panda::Local<panda::ObjectRef> exception = trycatch.GetAndClearException();
    if (!exception.IsEmpty() && !exception->IsHole()) {
        napi_value obj = ArkNativeEngine::ArkValueToNapiValue(env_, exception);
        CallbackTask(obj);
    }
}


void NapiUncaughtExceptionCallback::CallbackTask(napi_value& obj)
{
    std::string errorMsg = GetNativeStrFromJsTaggedObj(obj, "message");
    std::string errorName = GetNativeStrFromJsTaggedObj(obj, "name");
    std::string errorStack = GetNativeStrFromJsTaggedObj(obj, "stack");
    std::string topStack = GetNativeStrFromJsTaggedObj(obj, "topstack");
    std::string summary = "Error name:" + errorName + "\n";
    summary += "Error message:" + errorMsg + "\n";
    const JsEnv::ErrorObject errorObj = {
        .name = errorName,
        .message = errorMsg,
        .stack = errorStack
    };
    bool hasProperty = false;
    napi_has_named_property(env_, obj, "code", &hasProperty);
    if (hasProperty) {
        std::string errorCode = GetNativeStrFromJsTaggedObj(obj, "code");
        summary += "Error code:" + errorCode + "\n";
    }
    if (errorStack.empty()) {
        TAG_LOGE(AAFwkTag::JSENV, "errorStack is empty");
        return;
    }
    auto errorPos = SourceMap::GetErrorPos(topStack);
    std::string error;
    if (obj != nullptr) {
        napi_value fuc = nullptr;
        napi_get_named_property(env_, obj, "errorfunc", &fuc);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env_, fuc, &valueType);
        if (valueType == napi_function) {
            error = reinterpret_cast<NativeEngine*>(env_)->GetSourceCodeInfo(fuc, errorPos);
        }
    }
    if (errorStack.find(BACKTRACE) != std::string::npos) {
        summary += error + "Stacktrace:\n" + GetFuncNameAndBuildId(errorStack);
    } else {
        summary += error + "Stacktrace:\n" + errorStack;
    }
#ifdef SUPPORT_GRAPHICS
    std::string str = Ace::UIContent::GetCurrentUIStackInfo();
    if (!str.empty()) {
        summary.append(str);
    }
#endif // SUPPORT_GRAPHICS
    if (uncaughtTask_) {
        uncaughtTask_(summary, errorObj);
    }
}

std::string NapiUncaughtExceptionCallback::GetFuncNameAndBuildId(std::string nativeStack)
{
    std::stringstream ss(nativeStack);
    std::string tempStr;
    std::string appendInfo;
    // Filter two lines
    std::getline(ss, tempStr); // Cannot get SourceMap info, dump raw stack:
    std::getline(ss, tempStr); // =====================Backtrace========================
    HiviewDFX::UnwinderConfig::SetEnableMiniDebugInfo(true);
    HiviewDFX::UnwinderConfig::SetEnableLoadSymbolLazily(true);
    while (std::getline(ss, tempStr)) {
        auto splitPos = tempStr.rfind(" ");
        if (splitPos == std::string::npos) {
            return nativeStack;
        }
        HiviewDFX::RegularElfFactory elfFactory(tempStr.substr(splitPos + 1));
        auto elfFile = elfFactory.Create();
        std::string pc;
        size_t pcPos = tempStr.find(" pc ");
        if (pcPos == std::string::npos) {
            return nativeStack;
        }
        pc = tempStr.substr(pcPos += FLAG_PC_POS, FLAG_SPLIT_POS);
        uint64_t value;
        auto res = std::from_chars(pc.data(), pc.data() + pc.size(), value, FLAG_SPLIT_POS);
        if (res.ec != std::errc()) {
            return nativeStack;
        }
        std::string funcName;
        uint64_t funcOffset;
        HiviewDFX::DfxSymbols::GetFuncNameAndOffsetByPc(value, elfFile, funcName, funcOffset);
        std::string buildId = elfFile->GetBuildId();
        if (!funcName.empty()) {
            appendInfo += tempStr + "(" + funcName;
            appendInfo += HiviewDFX::StringPrintf("+%" PRId64, funcOffset) + ")";
            if (!buildId.empty()) {
                appendInfo += "(" + buildId + ")" + "\n";
            } else {
                appendInfo += "\n";
            }
        } else {
            if (!buildId.empty()) {
                appendInfo += tempStr + "(" + buildId + ")" + "\n";
            } else {
                appendInfo += tempStr + "\n";
            }
        }
    }
    return appendInfo;
}
} // namespace JsEnv
} // namespace OHOS
