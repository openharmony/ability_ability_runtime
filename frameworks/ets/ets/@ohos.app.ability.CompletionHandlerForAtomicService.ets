/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

export enum FailureCode {
    FAILURE_CODE_SYSTEM_MALFUNCTION = 0,
    FAILURE_CODE_USER_CANCEL = 1,
    FAILURE_CODE_USER_REFUSE = 2,
}

type OnAtomicServiceRequestSuccessFn = (appId: string) => void;

type OnAtomicServiceRequestFailureFn = (appId: string, failureCode: FailureCode, failureMessage: string) => void;

export default class CompletionHandlerForAtomicService {
    onAtomicServiceRequestSuccess?: OnAtomicServiceRequestSuccessFn;
    onAtomicServiceRequestFailure?: OnAtomicServiceRequestFailureFn;
}