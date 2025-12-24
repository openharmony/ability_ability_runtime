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

export type OnRequestSuccessFn = (name: string) => void;
export type OnRequestFailureFn = (name: string, failureCode: AbilityStartFailureCode, failureMessage: string) => void;

export class CompletionHandlerForAbilityStartCallback {
    onRequestSuccess?: OnRequestSuccessFn;
    onRequestFailure?: OnRequestFailureFn;
}

export enum AbilityStartFailureCode {
    FAILURE_CODE_SYSTEM_MALFUNCTION = 0,
    FAILURE_CODE_USER_CANCEL = 1
}
