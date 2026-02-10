/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_UTIL_H
#define OHOS_MOCK_UTIL_H

#include <any>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

// inner utils class, you should not use this.
class ResultWrap {
public:
    ResultWrap(std::any result)
    {
        result_ = result;
    }

    ResultWrap() {}

    template <typename T>
    T Get() const
    {
        return std::any_cast<T>(result_);
    }
private:
    std::any result_;
};

// donnot use or change this map.
inline thread_local std::map<std::string, std::vector<ResultWrap>> g_mockMap;
inline thread_local std::map<std::string, std::vector<std::vector<ResultWrap>>> g_RefMap;

// Tag dispatch for creating ResultWrap
namespace Detail {
    struct GenericTag {};
    struct BoolRefTag {};

    // Generic version
    template<typename T>
    inline ResultWrap CreateResultWrapImpl(T&& val, GenericTag) {
        return ResultWrap(std::forward<T>(val));
    }

    // Specialized version for vector<bool>::reference
    inline ResultWrap CreateResultWrapImpl(std::vector<bool>::reference val, BoolRefTag) {
        return ResultWrap(static_cast<bool>(val));
    }

    // Type trait to determine which tag to use
    template<typename T>
    using ResultWrapTag = std::conditional_t<
        std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, std::vector<bool>::reference>,
        BoolRefTag,
        GenericTag
    >;
}

template<typename T>
inline ResultWrap CreateResultWrap(T&& val) {
    return Detail::CreateResultWrapImpl(std::forward<T>(val), Detail::ResultWrapTag<T>{});
}

/**
 * @brief Mock a member function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD(ret, className, funcName, ...)                              \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp;                                                                      \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a void member function.
 *        This macro creates a definition of a void function that can be mocked.
 *        Use this macro for functions that return void instead of OH_MOCK_METHOD.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_VOID_METHOD(className, funcName, ...)                            \
void funcName(__VA_ARGS__)                                                       \
{                                                                                \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                     \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                \
        std::vector<ResultWrap> expectRets;                                      \
        g_mockMap[key] = expectRets;                                             \
    }                                                                            \
    auto it = g_mockMap.find(key);                                               \
    if (it != g_mockMap.end()) {                                                 \
        std::vector<ResultWrap> expectRets = it->second;                         \
        if (!expectRets.empty()) {                                               \
            expectRets.erase(expectRets.begin());                                \
        }                                                                        \
        g_mockMap[key] = expectRets;                                             \
    }                                                                            \
}

/**
 * @brief Mock a member function with one output parameter.
 *        This macro handles functions with an output parameter (by reference).
 *        The output parameter can be at any position in the parameter list.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param oPName The name of the output parameter (will be set from mock expectations).
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate all the params of function (both input and output).
 *
 * Usage:
 *   // Function: int32_t CheckPhotoUriPermission(uint32_t, const std::vector<std::string>&, std::vector<bool>&,
 *   //     const std::vector<uint32_t>&)
 *   // Where 'results' (3rd param) is the output parameter
 *   OH_MOCK_METHOD_WITH_OUTPUT_1(int32_t, results, MediaPermissionHelper, CheckPhotoUriPermission,
 *       uint32_t, const std::vector<std::string>&, std::vector<bool>& results, const std::vector<uint32_t>&);
 *
 *   // Set expectations:
*    std::vector<std::vector<bool>> results = {{true, false}};
 *   OH_EXPECT_RET_AND_OUTPUT({ERR_OK}, results, MediaPermissionHelper, CheckPhotoUriPermission,
 *       uint32_t, const std::vector<std::string>&, std::vector<bool>& results, const std::vector<uint32_t>&);
 */
#define OH_MOCK_METHOD_WITH_OUTPUT_1(ret, oPName, className, funcName, ...)        \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp{};                                                                    \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    if (g_RefMap.find(key) == g_RefMap.end()) {                                    \
        std::vector<std::vector<ResultWrap>> expectRefs;                           \
        g_RefMap[key] = expectRefs;                                                \
    }                                                                              \
    std::remove_reference_t<decltype(oPName)> tempOp{};                            \
    ResultWrap tempRef(tempOp);                                                    \
    auto it1 = g_RefMap.find(key);                                                 \
    if (it1 != g_RefMap.end()) {                                                   \
        std::vector<std::vector<ResultWrap>> expectRefs = it1->second;             \
        if (!expectRefs.empty()) {                                                 \
            tempRef = expectRefs[0][0];                                            \
            expectRefs.erase(expectRefs.begin());                                  \
        }                                                                          \
        g_RefMap[key] = expectRefs;                                                \
    }                                                                              \
    oPName = tempRef.Get<decltype(tempOp)>();                                      \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a member function with vector output parameter.
 *        This macro handles functions where the output parameter is a vector type (e.g., std::vector<T>&).
 *        Unlike OH_MOCK_METHOD_WITH_OUTPUT_1 which handles scalar outputs,
 *        this macro extracts all elements from the expectation vector and assigns them to the output vector.
 * @param ret Indicate the type of return value.
 * @param oPName The name of the output parameter (will be set from mock expectations).
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate all the params of function (both input and output).
 *
 * Usage:
 *   // Function: int32_t CheckPhotoUriPermission(uint32_t, const std::vector<std::string>&, std::vector<bool>&,
     //     const std::vector<uint32_t>&)
 *   // Where 'results' (3rd param) is the vector output parameter
 *   OH_MOCK_METHOD_WITH_OUTPUT_VECTOR(int32_t, results, MediaPermissionHelper, CheckPhotoUriPermission,
 *       uint32_t, const std::vector<std::string>&, std::vector<bool>& results, const std::vector<uint32_t>&);
 *
 *   // Set expectations:
 *   std::vector<std::vector<bool>> results = {{true, false}};
 *   OH_EXPECT_RET_AND_OUTPUT({ERR_OK}, results, MediaPermissionHelper, CheckPhotoUriPermission,
 *       uint32_t, const std::vector<std::string>&, std::vector<bool>& results, const std::vector<uint32_t>&);
 */
#define OH_MOCK_METHOD_WITH_OUTPUT_VECTOR(ret, oPName, className, funcName, ...)               \
ret funcName(__VA_ARGS__)                                                                      \
{                                                                                              \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                                   \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                              \
        std::vector<ResultWrap> expectRets;                                                    \
        g_mockMap[key] = expectRets;                                                           \
    }                                                                                          \
    ret temp{};                                                                                \
    ResultWrap tempRet(temp);                                                                  \
    auto it = g_mockMap.find(key);                                                             \
    if (it != g_mockMap.end()) {                                                               \
        std::vector<ResultWrap> expectRets = it->second;                                       \
        if (!expectRets.empty()) {                                                             \
            tempRet = expectRets[0];                                                           \
            expectRets.erase(expectRets.begin());                                              \
        }                                                                                      \
        g_mockMap[key] = expectRets;                                                           \
    }                                                                                          \
    if (g_RefMap.find(key) == g_RefMap.end()) {                                                \
        std::vector<std::vector<ResultWrap>> expectRefs;                                       \
        g_RefMap[key] = expectRefs;                                                            \
    }                                                                                          \
    std::remove_reference_t<decltype(oPName)> tempOp{};                                        \
    auto it1 = g_RefMap.find(key);                                                             \
    if (it1 != g_RefMap.end()) {                                                               \
        std::vector<std::vector<ResultWrap>> expectRefs = it1->second;                         \
        if (!expectRefs.empty()) {                                                             \
            auto& singleCallResults = expectRefs[0];                                           \
            tempOp.reserve(singleCallResults.size());                                          \
            for (auto& resultWrap : singleCallResults) {                                       \
                using ElementType = typename std::remove_reference_t<decltype(oPName)>::value_type; \
                tempOp.push_back(resultWrap.Get<ElementType>());                               \
            }                                                                                  \
            expectRefs.erase(expectRefs.begin());                                              \
        }                                                                                      \
        g_RefMap[key] = expectRefs;                                                            \
    }                                                                                          \
    oPName = tempOp;                                                                           \
    return tempRet.Get<ret>();                                                                 \
}

/**
 * @brief Mock a member function with return sptr<xxx> type value.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: ret must be sptr<xxx>
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_RET_SPTR(ret, className, funcName, ...)                     \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> tempExpectRets;                                    \
        g_mockMap[key] = tempExpectRets;                                           \
    }                                                                              \
    ret tmp = nullptr;                                                             \
    ResultWrap tempRet(tmp);                                                       \
    std::vector<ResultWrap>& expectRets = g_mockMap[key];                          \
    if (!expectRets.empty()) {                                                     \
        tempRet = expectRets[0];                                                   \
        expectRets.erase(expectRets.begin());                                      \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}                                                                                  \

/**
 * @brief Mock a member function with decorator and return sptr<xxx> type value.
 *        This macro creates a definition of a function with decorator (e.g., static, virtual, constexpr)
 *        that returns sptr<T> type and can be mocked.
 *        Use this macro for methods with decorators that return sptr<xxx> type values.
 * @param decorator Indicate the decorator of function (e.g., static, virtual, constexpr).
 * @param ret Indicate the type of return value.
 *            Warning: ret must be sptr<xxx>
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_RET_SPTR_WITH_DECORATOR(decorator, ret, className, funcName, ...) \
decorator ret funcName(__VA_ARGS__)                                                  \
{                                                                                    \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                         \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                    \
        std::vector<ResultWrap> tempExpectRets;                                      \
        g_mockMap[key] = tempExpectRets;                                             \
    }                                                                                \
    ret tmp = nullptr;                                                               \
    ResultWrap tempRet(tmp);                                                         \
    auto it = g_mockMap.find(key);                                                   \
    if (it != g_mockMap.end()) {                                                     \
        std::vector<ResultWrap> expectRets = it->second;                             \
        if (!expectRets.empty()) {                                                   \
            tempRet = expectRets[0];                                                 \
            expectRets.erase(expectRets.begin());                                    \
        }                                                                            \
        g_mockMap[key] = expectRets;                                                 \
    }                                                                                \
    return tempRet.Get<ret>();                                                       \
}

/**
 * @brief Mock a virtual or static member function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_WITH_DECORATOR(decorator, ret, className, funcName, ...)    \
decorator ret funcName(__VA_ARGS__)                                                \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp{};                                                                    \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a void function with decorator (e.g., static, inline, etc.).
 *        Use this macro for void functions that need a decorator like static.
 * @param decorator Indicate the decorator of function (e.g., static, inline).
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_VOID_METHOD_WITH_DECORATOR(decorator, className, funcName, ...)    \
decorator void funcName(__VA_ARGS__)                                           \
{                                                                              \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                   \
    if (g_mockMap.find(key) == g_mockMap.end()) {                              \
        std::vector<ResultWrap> expectRets;                                    \
        g_mockMap[key] = expectRets;                                           \
    }                                                                          \
    auto it = g_mockMap.find(key);                                             \
    if (it != g_mockMap.end()) {                                               \
        std::vector<ResultWrap> expectRets = it->second;                       \
        if (!expectRets.empty()) {                                             \
            expectRets.erase(expectRets.begin());                              \
        }                                                                      \
        g_mockMap[key] = expectRets;                                           \
    }                                                                          \
}

/**
 * @brief Mock function body - use this macro inside a function definition to generate mock logic.
 *        This is useful for functions with default parameters where you need to manually declare the function.
 * @param ret Return type
 * @param className Class name for key generation
 * @param funcName Function name
 * @param paramTypesStr Parameter types as a string literal (e.g., "Uri&, uint32_t, const std::string&")
 */
#define OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY(ret, className, funcName, paramTypesStr) \
do {                                                                           \
    std::string key = #className"_"#funcName"_" + std::string(paramTypesStr);  \
    if (g_mockMap.find(key) == g_mockMap.end()) {                              \
        std::vector<ResultWrap> expectRets;                                    \
        g_mockMap[key] = expectRets;                                           \
    }                                                                          \
    ret temp{};                                                                \
    ResultWrap tempRet(temp);                                                  \
    auto it = g_mockMap.find(key);                                             \
    if (it != g_mockMap.end()) {                                               \
        std::vector<ResultWrap> expectRets = it->second;                       \
        if (!expectRets.empty()) {                                             \
            tempRet = expectRets[0];                                           \
            expectRets.erase(expectRets.begin());                              \
        }                                                                      \
        g_mockMap[key] = expectRets;                                           \
    }                                                                          \
    return tempRet.Get<ret>();                                                 \
} while (0)

/**
 * @brief Mock a virtual or static member function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX(prefix, suffix, ret, className, funcName, ...)    \
prefix ret funcName(__VA_ARGS__) suffix                                                \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp{};                                                                    \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a static/virtual member function with one output parameter.
 *        This macro handles functions with decorator (static/virtual) and an output parameter.
 * @param decorator Function decorator, e.g., static, virtual
 * @param ret Indicate the type of return value.
 * @param oPName The name of the output parameter (will be set from mock expectations).
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate all the params of function (both input and output).
 *
 * Usage:
 *   // Static function: int GetHapTokenInfo(uint32_t, HapTokenInfo&)
 *   OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1(static, int, hapInfo, AccessTokenKit, GetHapTokenInfo,
 *       uint32_t, HapTokenInfo& hapInfo);
 *
 *   // Set expectations:
 *   HapTokenInfo hapInfo;
 *   hapInfo.accessTokenIdEx = 100;
 *   std::vector<HapTokenInfo> expectResults = {hapInfo},
 *   OH_EXPECT_RET_AND_OUTPUT({RET_SUCCESS},  AccessTokenKit, GetHapTokenInfo,
 *       uint32_t, HapTokenInfo& hapInfo);
 */
#define OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1(decorator, ret, oPName, className, funcName, ...) \
decorator ret funcName(__VA_ARGS__)                                                       \
{                                                                                         \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                              \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                         \
        std::vector<ResultWrap> expectRets;                                               \
        g_mockMap[key] = expectRets;                                                      \
    }                                                                                     \
    ret temp{};                                                                           \
    ResultWrap tempRet(temp);                                                             \
    auto it = g_mockMap.find(key);                                                        \
    if (it != g_mockMap.end()) {                                                          \
        std::vector<ResultWrap> expectRets = it->second;                                  \
        if (!expectRets.empty()) {                                                        \
            tempRet = expectRets[0];                                                      \
            expectRets.erase(expectRets.begin());                                         \
        }                                                                                 \
        g_mockMap[key] = expectRets;                                                      \
    }                                                                                     \
    if (g_RefMap.find(key) == g_RefMap.end()) {                                           \
        std::vector<std::vector<ResultWrap>> expectRefs;                                  \
        g_RefMap[key] = expectRefs;                                                       \
    }                                                                                     \
    std::remove_reference_t<decltype(oPName)> tempOp{};                                   \
    ResultWrap tempRef(tempOp);                                                           \
    auto it1 = g_RefMap.find(key);                                                        \
    if (it1 != g_RefMap.end()) {                                                          \
        std::vector<std::vector<ResultWrap>> expectRefs = it1->second;                    \
        if (!expectRefs.empty()) {                                                        \
            tempRef = expectRefs[0][0];                                                   \
            expectRefs.erase(expectRefs.begin());                                         \
        }                                                                                 \
        g_RefMap[key] = expectRefs;                                                       \
    }                                                                                     \
    oPName = tempRef.Get<decltype(tempOp)>();                                             \
    return tempRet.Get<ret>();                                                            \
}

/**
 * @brief Mock a global function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_GLOBAL_METHOD(ret, funcName, ...)                                   \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #funcName"_"#__VA_ARGS__;                                    \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> tempExpectRets;                                    \
        g_mockMap[key] = tempExpectRets;                                           \
    }                                                                              \
    ret temp{};                                                                    \
    ResultWrap tempRet(temp);                                                      \
    std::vector<ResultWrap>& expectRets = g_mockMap[key];                          \
    if (!expectRets.empty()) {                                                     \
        tempRet = expectRets[0];                                                   \
        expectRets.erase(expectRets.begin());                                      \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a global void function.
 *        This macro creates a definition of a void global function that can be mocked.
 *        Use this macro for global functions that return void instead of OH_MOCK_GLOBAL_METHOD.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_GLOBAL_VOID_METHOD(funcName, ...)                              \
void funcName(__VA_ARGS__)                                                     \
{                                                                              \
    std::string key = #funcName"_"#__VA_ARGS__;                                \
    if (g_mockMap.find(key) == g_mockMap.end()) {                              \
        std::vector<ResultWrap> expectRets;                                    \
        g_mockMap[key] = expectRets;                                           \
    }                                                                          \
    auto it = g_mockMap.find(key);                                             \
    if (it != g_mockMap.end()) {                                               \
        std::vector<ResultWrap> expectRets = it->second;                       \
        if (!expectRets.empty()) {                                             \
            expectRets.erase(expectRets.begin());                              \
        }                                                                      \
        g_mockMap[key] = expectRets;                                           \
    }                                                                          \
}

/**
 * @brief Mock a global template function with return sptr<xxx> type value.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: ret must be sptr<xxx>
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_GLOBAL_TEMPLATE_METHOD_RET_SPTR(funcName, ...)                     \
template <typename INTERFACE> sptr<INTERFACE> funcName(__VA_ARGS__)                \
{                                                                                  \
    std::string key = #funcName"_"#__VA_ARGS__;                                    \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> tempExpectRets;                                    \
        g_mockMap[key] = tempExpectRets;                                           \
    }                                                                              \
    sptr<INTERFACE> tmp = nullptr;                                                 \
    ResultWrap tempRet(tmp);                                                       \
    std::vector<ResultWrap>& expectRets = g_mockMap[key];                          \
    if (!expectRets.empty()) {                                                     \
        tempRet = expectRets[0];                                                   \
        expectRets.erase(expectRets.begin());                                      \
    }                                                                              \
    return tempRet.Get<sptr<INTERFACE>>();                                         \
}

/**
 * @brief Mock a member function with decorator and vector output parameter.
 *        This macro handles functions with decorator (static/virtual) and a vector output parameter.
 * @param decorator Function decorator, e.g., static, virtual
 * @param ret Indicate the type of return value.
 * @param oPName The name of the vector output parameter (will be set from mock expectations).
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate all the params of function (both input and output).
 *
 * Usage:
 *   // Static function: int32_t CheckData(uint32_t, const std::vector<std::string>&, std::vector<bool>&)
 *   // Where 'results' (3rd param) is the vector output parameter
 *   OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR(static, int32_t, results, MediaPermissionHelper,
 *       CheckPhotoUriPermission, uint32_t, const std::vector<std::string>&, std::vector<bool>& results);
 *
 *   // Set expectations:
 *   std::vector<std::vector<bool>> results = {{true, false}, {false, true}};
 *   OH_EXPECT_RET_AND_OUTPUT({ERR_OK, ERR_OK}, results, MediaPermissionHelper, CheckPhotoUriPermission,
 *       uint32_t, const std::vector<std::string>&, std::vector<bool>& results);
 */
#define OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR(decorator, ret, oPName, className, funcName, ...) \
decorator ret funcName(__VA_ARGS__)                                                       \
{                                                                                         \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                              \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                         \
        std::vector<ResultWrap> expectRets;                                               \
        g_mockMap[key] = expectRets;                                                      \
    }                                                                                     \
    ret temp{};                                                                           \
    ResultWrap tempRet(temp);                                                             \
    auto it = g_mockMap.find(key);                                                        \
    if (it != g_mockMap.end()) {                                                          \
        std::vector<ResultWrap> expectRets = it->second;                                  \
        if (!expectRets.empty()) {                                                        \
            tempRet = expectRets[0];                                                      \
            expectRets.erase(expectRets.begin());                                         \
        }                                                                                 \
        g_mockMap[key] = expectRets;                                                      \
    }                                                                                     \
    if (g_RefMap.find(key) == g_RefMap.end()) {                                           \
        std::vector<std::vector<ResultWrap>> expectRefs;                                  \
        g_RefMap[key] = expectRefs;                                                       \
    }                                                                                     \
    std::remove_reference_t<decltype(oPName)> tempOp{};                                   \
    auto it1 = g_RefMap.find(key);                                                        \
    if (it1 != g_RefMap.end()) {                                                          \
        std::vector<std::vector<ResultWrap>> expectRefs = it1->second;                    \
        if (!expectRefs.empty()) {                                                        \
            auto& singleCallResults = expectRefs[0];                                      \
            tempOp.reserve(singleCallResults.size());                                     \
            for (auto& resultWrap : singleCallResults) {                                  \
                using ElementType = typename std::remove_reference_t<decltype(oPName)>::value_type; \
                tempOp.push_back(resultWrap.Get<ElementType>());                          \
            }                                                                             \
            expectRefs.erase(expectRefs.begin());                                         \
        }                                                                                 \
        g_RefMap[key] = expectRefs;                                                       \
    }                                                                                     \
    oPName = tempOp;                                                                      \
    return tempRet.Get<ret>();                                                            \
}

/**
 * @brief Mock a serial of expect results for specified member function.
 * @param expectRetVec Indicate expect results vector.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_EXPECT_RET(expectRetVec, className, funcName, ...)                      \
do {                                                                               \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    std::vector<ResultWrap> v;                                                     \
    for (auto e : expectRetVec) {                                                  \
        v.emplace_back(CreateResultWrap(e));                                       \
    }                                                                              \
    g_mockMap[key] = v;                                                            \
} while (0)

/**
 * @brief Mock a serial of expect results for specified member function.
 * @param expectRetVec Indicate expect results vector.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_EXPECT_RET_AND_OUTPUT(expectRetVec, expectOutputVec, className, funcName, ...)  \
do {                                                                                       \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                               \
    std::vector<ResultWrap> v;                                                             \
    for (auto e : expectRetVec) {                                                          \
        v.emplace_back(CreateResultWrap(e));                                               \
    }                                                                                      \
    g_mockMap[key] = v;                                                                    \
    std::vector<std::vector<ResultWrap>> vRefs;                                            \
    for (auto eOuters : expectOutputVec) {                                                 \
        std::vector<ResultWrap> vRef;                                                      \
        for (auto eOuter : eOuters) {                                                      \
            vRef.emplace_back(CreateResultWrap(eOuter));                                   \
        }                                                                                  \
        vRefs.emplace_back(vRef);                                                          \
    }                                                                                      \
    g_RefMap[key] = vRefs;                                                                 \
} while (0)

/**
 * @brief Mock a serial of expect results for specified global function.
 * @param expectRetVec Indicate expect results vector.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_GLOBAL_EXPECT_RET(expectRetVec, funcName, ...)                          \
do {                                                                               \
    std::string key = #funcName"_"#__VA_ARGS__;                                    \
    std::vector<ResultWrap> v;                                                     \
    for (auto e : expectRetVec) {                                                  \
        ResultWrap r(e);                                                           \
        v.emplace_back(r);                                                         \
    }                                                                              \
    g_mockMap[key] = v;                                                            \
} while (0)

#endif  // OHOS_MOCK_UTIL_H