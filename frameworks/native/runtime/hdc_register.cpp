/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "hdc_register.h"

#include <dlfcn.h>
#include <unistd.h>

#include "hilog_tag_wrapper.h"

namespace OHOS::AbilityRuntime {
using StartRegister = void (*)(const std::string& processName, const std::string& pkgName, bool isDebug,
    const HdcRegisterCallback& callback);
using StopRegister = void (*)();

HdcRegister::~HdcRegister()
{
    StopHdcRegister();
}

HdcRegister& HdcRegister::Get()
{
    static HdcRegister hdcRegister;
    return hdcRegister;
}

void HdcRegister::StartHdcRegister(const std::string& bundleName, const std::string& processName, bool debugApp,
    DebugRegisterMode debugMode, HdcRegisterCallback callback)
{
    TAG_LOGD(AAFwkTag::JSRUNTIME, "called");

    if (debugMode == BOTH_REG) {
        registerLocalHandler_ = dlopen("libda_register.z.so", RTLD_LAZY);
        registerHdcHandler_ = dlopen("libhdc_register.z.so", RTLD_LAZY);
    } else if (debugMode == LOCAL_DEBUG_REG) {
        registerLocalHandler_ = dlopen("libda_register.z.so", RTLD_LAZY);
    } else {
        registerHdcHandler_ = dlopen("libhdc_register.z.so", RTLD_LAZY);
    }
    if (registerLocalHandler_ != nullptr) {
        auto startRegister = reinterpret_cast<StartRegister>(dlsym(registerLocalHandler_, "StartConnect"));
        if (startRegister != nullptr) {
            startRegister(processName, bundleName, debugApp, callback);
        }
    } else {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "null registerLocalHandler_");
    }
    if (registerHdcHandler_ != nullptr) {
        auto startRegister = reinterpret_cast<StartRegister>(dlsym(registerHdcHandler_, "StartConnect"));
        if (startRegister != nullptr) {
            startRegister(processName, bundleName, debugApp, callback);
        }
    } else {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "null registerHdcHandler_");
    }
}

void HdcRegister::StopHdcRegister()
{
    TAG_LOGD(AAFwkTag::JSRUNTIME, "called");

    if (registerLocalHandler_ != nullptr) {
        auto stopRegister = reinterpret_cast<StopRegister>(dlsym(registerLocalHandler_, "StopConnect"));
        if (stopRegister != nullptr) {
            stopRegister();
        } else {
            TAG_LOGE(AAFwkTag::JSRUNTIME, "null StopConnect");
        }
        dlclose(registerLocalHandler_);
        registerLocalHandler_ = nullptr;
    } else {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "null registerLocalHandler_");
    }

    if (registerHdcHandler_ != nullptr) {
        auto stopRegister = reinterpret_cast<StopRegister>(dlsym(registerHdcHandler_, "StopConnect"));
        if (stopRegister != nullptr) {
            stopRegister();
        } else {
            TAG_LOGE(AAFwkTag::JSRUNTIME, "null StopConnect");
        }
        dlclose(registerHdcHandler_);
        registerHdcHandler_ = nullptr;
    } else {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "null registerHdcHandler_");
    }
}
} // namespace OHOS::AbilityRuntime
