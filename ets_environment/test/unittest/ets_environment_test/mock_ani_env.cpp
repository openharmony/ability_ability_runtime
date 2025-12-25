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
#include "mock_ani_env.h"

namespace OHOS {
namespace EtsEnv {

MockAniEnv::State MockAniEnv::state_;

MockAniEnv::MockAniEnv()
{
    api_.GetUndefined = &MockAniEnv::GetUndefined;
    api_.Array_New = &MockAniEnv::ArrayNew;
    api_.String_NewUTF8 = &MockAniEnv::StringNewUtf8;
    api_.Array_Set = &MockAniEnv::ArraySet;
    api_.Object_CallMethodByName_Void_V = &MockAniEnv::CallMethodVoid;

    api_.FindClass = &MockAniEnv::FindClass;
    api_.Class_FindMethod = &MockAniEnv::ClassFindMethod;
    api_.Class_FindField = &MockAniEnv::ClassFindField;
    api_.Object_New_V = &MockAniEnv::ObjectNew;
    api_.Object_GetField_Long = &MockAniEnv::ObjectGetFieldLong;
    api_.Object_SetField_Long = &MockAniEnv::ObjectSetFieldLong;
    api_.GlobalReference_Create = &MockAniEnv::GlobalReferenceCreate;
    api_.GlobalReference_Delete = &MockAniEnv::GlobalReferenceDelete;
    api_.Class_CallStaticMethodByName_Void_V = &MockAniEnv::ClassCallStaticMethodByNameVoid;

    env_.c_api = &api_;

    MockAniEnv::state_.getUndefinedStatus = ANI_OK;
    MockAniEnv::state_.arrayNewStatus = ANI_OK;
    MockAniEnv::state_.stringNewStatus = ANI_OK;
    MockAniEnv::state_.arraySetStatus = ANI_OK;
    MockAniEnv::state_.callMethodStatus = ANI_OK;
    MockAniEnv::state_.findClassStatus = ANI_OK;
    MockAniEnv::state_.classFindMethodStatus = ANI_OK;
    MockAniEnv::state_.classFindFieldStatus = ANI_OK;
    MockAniEnv::state_.objectNewStatus = ANI_OK;
    MockAniEnv::state_.objectGetFieldLongStatus = ANI_OK;
    MockAniEnv::state_.objectSetFieldLongStatus = ANI_OK;
    MockAniEnv::state_.globalRefCreateStatus = ANI_OK;
    MockAniEnv::state_.globalRefDeleteStatus = ANI_OK;
    MockAniEnv::state_.arrayNewRefStatus = ANI_OK;
    MockAniEnv::state_.arraySetRefStatus = ANI_OK;
    MockAniEnv::state_.classCallStaticMethodStatus = ANI_OK;
}

ani_env *MockAniEnv::GetEnv()
{
    return &env_;
}

MockAniEnv::State &MockAniEnv::GetState()
{
    return MockAniEnv::state_;
}

ani_status MockAniEnv::GetUndefined(ani_env *env, ani_ref *result)
{
    if (MockAniEnv::state_.getUndefinedStatus != ANI_OK) {
        return MockAniEnv::state_.getUndefinedStatus;
    }
    *result = reinterpret_cast<ani_ref>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ArrayNew(ani_env *env, ani_size length, ani_ref initValue, ani_array *result)
{
    if (MockAniEnv::state_.arrayNewStatus != ANI_OK) {
        return MockAniEnv::state_.arrayNewStatus;
    }
    *result = reinterpret_cast<ani_array>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ArrayNewRef(ani_env *env, ani_type type, ani_size length,
    ani_ref initValue, ani_array *result)
{
    if (MockAniEnv::state_.arrayNewRefStatus != ANI_OK) {
        return MockAniEnv::state_.arrayNewRefStatus;
    }
    *result = reinterpret_cast<ani_array>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::StringNewUtf8(ani_env *env, const char *utf8, ani_size len, ani_string *result)
{
    if (MockAniEnv::state_.stringNewStatus != ANI_OK) {
        return MockAniEnv::state_.stringNewStatus;
    }
    *result = reinterpret_cast<ani_string>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ArraySet(ani_env *env, ani_array array, ani_size index, ani_ref value)
{
    return MockAniEnv::state_.arraySetStatus;
}

ani_status MockAniEnv::ArraySetRef(ani_env *env, ani_array array, ani_size index, ani_ref value)
{
    return MockAniEnv::state_.arraySetRefStatus;
}

ani_status MockAniEnv::CallMethodVoid(ani_env *env, ani_object obj, const char *name, const char *sig, va_list args)
{
    return MockAniEnv::state_.callMethodStatus;
}

ani_status MockAniEnv::ClassCallStaticMethodByNameVoid(ani_env *env, ani_class cls, const char *name,
    const char *sig, va_list args)
{
    return MockAniEnv::state_.classCallStaticMethodStatus;
}

ani_status MockAniEnv::FindClass(ani_env *env, const char *name, ani_class *cls)
{
    if (MockAniEnv::state_.findClassStatus != ANI_OK) {
        return MockAniEnv::state_.findClassStatus;
    }
    *cls = reinterpret_cast<ani_class>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ClassFindMethod(ani_env *env, ani_class cls, const char *name, const char *sig,
    ani_method *method)
{
    if (MockAniEnv::state_.classFindMethodStatus != ANI_OK) {
        return MockAniEnv::state_.classFindMethodStatus;
    }
    *method = reinterpret_cast<ani_method>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ClassFindField(ani_env *env, ani_class cls, const char *name, ani_field *field)
{
    if (MockAniEnv::state_.classFindFieldStatus != ANI_OK) {
        return MockAniEnv::state_.classFindFieldStatus;
    }
    *field = reinterpret_cast<ani_field>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ObjectNew(ani_env *env, ani_class cls, ani_method method, ani_object *result, va_list args)
{
    if (MockAniEnv::state_.objectNewStatus != ANI_OK) {
        return MockAniEnv::state_.objectNewStatus;
    }
    *result = reinterpret_cast<ani_object>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::ObjectGetFieldLong(ani_env *env, ani_object obj, ani_field field, ani_long *result)
{
    if (MockAniEnv::state_.objectGetFieldLongStatus != ANI_OK) {
        return MockAniEnv::state_.objectGetFieldLongStatus;
    }
    *result = static_cast<ani_long>(0);
    return ANI_OK;
}

ani_status MockAniEnv::ObjectSetFieldLong(ani_env *env, ani_object obj, ani_field field, ani_long value)
{
    return MockAniEnv::state_.objectSetFieldLongStatus;
}

ani_status MockAniEnv::GlobalReferenceCreate(ani_env *env, ani_ref ref, ani_ref *result)
{
    if (MockAniEnv::state_.globalRefCreateStatus != ANI_OK) {
        return MockAniEnv::state_.globalRefCreateStatus;
    }
    *result = reinterpret_cast<ani_object>(0x11);
    return ANI_OK;
}

ani_status MockAniEnv::GlobalReferenceDelete(ani_env *env, ani_ref ref)
{
    return MockAniEnv::state_.globalRefDeleteStatus;
}
} // namespace EtsEnv
} // namespace OHOS
