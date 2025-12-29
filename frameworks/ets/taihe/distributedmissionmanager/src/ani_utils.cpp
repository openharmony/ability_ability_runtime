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
#define LOG_TAG "AniUtils"
#include "ani_utils.h"
#include "hilog_tag_wrapper.h"

namespace ani_utils {

ani_status AniCreateInt(ani_env* env, int32_t value, ani_object& result)
{
    ani_status state;
    ani_class intClass;
    if ((state = env->FindClass("std.core.Int", &intClass)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "FindClass std/core/Int failed, %{public}d", state);
        return state;
    }
    ani_method intClassCtor;
    if ((state = env->Class_FindMethod(intClass, "<ctor>", "i:", &intClassCtor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "Class_FindMethod Int ctor failed, %{public}d", state);
        return state;
    }
    ani_int aniValue = value;
    if ((state = env->Object_New(intClass, intClassCtor, &result, aniValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "New Int object failed, %{public}d", state);
    }
    if (state != ANI_OK) {
        result = nullptr;
    }
    return state;
}

void AniExecuteFunc(ani_vm* vm, const std::function<void(ani_env*)> func)
{
    TAG_LOGI(AAFwkTag::MISSION, "AniExecutePromise");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "AniExecutePromise, vm error");
        return;
    }
    ani_boolean unhandleException = false;
    ani_env *currentEnv = nullptr;
    ani_status aniResult = vm->GetEnv(ANI_VERSION_1, &currentEnv);
    if (ANI_OK == aniResult && currentEnv != nullptr) {
        TAG_LOGI(AAFwkTag::MISSION, "AniExecutePromise, env exist");
        func(currentEnv);
        if (currentEnv->ExistUnhandledError(&unhandleException) && unhandleException) {
            TAG_LOGE(AAFwkTag::MISSION, "AniExecuteFunc, unhandleException, reset");
            currentEnv->ResetError();
        }
        return;
    }

    ani_env* newEnv = nullptr;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &newEnv);
    if (ANI_OK != aniResult || newEnv == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "AniExecutePromise, AttachCurrentThread error");
        return;
    }
    func(newEnv);
    if (newEnv->ExistUnhandledError(&unhandleException) && unhandleException) {
        TAG_LOGE(AAFwkTag::MISSION, "AniExecuteFunc, unhandleException, reset");
        newEnv->ResetError();
    }
    aniResult = vm->DetachCurrentThread();
    if (ANI_OK != aniResult) {
        TAG_LOGE(AAFwkTag::MISSION, "AniExecutePromise, DetachCurrentThread error");
        return;
    }
}

} //namespace ani_utils